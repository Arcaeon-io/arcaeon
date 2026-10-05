# Rekor rewrite plan: anchoring a sealed envelope

Status: plan plus an offline skeleton (`src/arcaeon/remote/rekor_anchor.py`,
`ARMED = False`). Nothing in this plan sends anything until the owner arms it.

## In one paragraph

A sealed envelope is a DSSE envelope. Its signature covers one byte string,
`PAE(payloadType, payload)`. We anchor `sha256` of that string in three
places: a `hashedrekord` entry on the public Rekor v1 log, an RFC 3161
time-stamp token from a time-stamping authority (TSA), and an OpenTimestamps
(OTS) proof. The envelope itself stays in our own bundle. Each anchor is a
separate file next to the bundle, never inside it. Each anchor is read on its
own and answers VERIFIED, BROKEN or COULD NOT LOOK. The envelope's verdict
never depends on the network.

## What changes from the current pin

The hosted witness already has a Rekor pin. It is not in this repo, and it
stays armed off. It signs `sha256` of a pin statement file (a small canonical
JSON naming a chain head) and builds a `hashedrekord` v0.0.1 body for that
digest.

| | current pin | this plan |
|---|---|---|
| what is hashed | the pin statement file's bytes | `PAE(payloadType, payload)` of the envelope |
| what it binds | a ledger head | the exact bytes the envelope signature covers |
| Rekor type | `hashedrekord` 0.0.1 on v1 | the same |
| the clock | Rekor v1's integrated time | an RFC 3161 TSA token, with v1 integrated time read as a second clock |
| OTS | stamps the same statement digest | stamps the PAE digest, kept as `BUNDLE.ots` |
| several witnesses | one key | one bundle per witness |

The entry type and log stay the same. What changes is the digest: it moves
from "a statement about a chain" to "the signed bytes of one envelope".

## The entry shape

A Rekor v1 `hashedrekord`, `apiVersion` `0.0.1`:

```json
{
 "apiVersion": "0.0.1",
 "kind": "hashedrekord",
 "spec": {
  "data": {"hash": {"algorithm": "sha256", "value": "<sha256(PAE) hex>"}},
  "signature": {
   "content": "<base64 witness signature>",
   "publicKey": {"content": "<base64 of the witness public key PEM>"}
  }
 }
}
```

- `data.hash.value` is `sha256(PAE(payloadType, payload))` of the envelope
  (`envelope_digest`). The signatures are not part of it, so every witness of
  one envelope names the same digest.
- `signature.content` is the witness key's ECDSA P-256 signature, made with
  SHA-256 over the PAE bytes. Rekor checks it against `data.hash`.
- `publicKey.content` is the witness public key as a PEM `PUBLIC KEY` block.
  `compose_hashedrekord` refuses anything else, including a private key.

The log keeps a digest, a signature and a public key, publicly and
permanently. It does not keep the envelope, the payload or the file.

## Why not the `dsse` type, and why not Rekor v2

- Rekor v2 (rekor-tiles) dropped the `dsse` entry type in v2.3.0. Sigstore's
  own SDKs now log a DSSE envelope as a `hashedrekord` over `sha256(PAE)`,
  which is the shape above. Rekor v1's `dsse` type stored only hashes too,
  never the envelope.
- Rekor v2 entries carry no integrated time (`integrated_time` is always 0),
  so a v2 entry says nothing about when on its own.
- The Sigstore public instance keeps Rekor v1 as the default for now. v2 is
  opt-in, and its shard URL rotates and is meant to be found through the
  signing config, never hard-coded.

So we write v1 `hashedrekord` today. The same digest, signature and key map
onto v2's `hashedRekordRequestV002` if we move later, and the TSA token
already supplies the time v2 would lack.

## The TSA token path

1. Make a nonce: a fresh positive 64-bit integer (`new_nonce`).
2. Build a DER `TimeStampReq` (`tsa_request`): version 1, `messageImprint` =
   sha256 with the PAE digest, the nonce, `certReq` true so the reply carries
   the TSA certificate. The bytes match what `openssl ts -query -sha256
   -digest <hex> -cert` writes for the same nonce; a test checks this.
3. Send it to the chosen TSA (armed path only, not built yet). Keep the
   request as `BUNDLE.tsq` and the reply as `BUNDLE.tsr`.

What `check_tsa_token` checks, offline:

| step | VERIFIED when | BROKEN when | COULD NOT LOOK when |
|---|---|---|---|
| token | the DER parses as a granted token holding a TSTInfo | | it does not parse, or the TSA refused |
| imprint | `messageImprint` is sha256 and equals the digest | it names another digest | it uses another hash |
| nonce | the token carries the nonce we sent | the nonce differs or is missing | |
| signature | the CMS signature covers this TSTInfo, the signer has the time-stamping key purpose, genTime falls inside the signer's validity, and the signer chains to a TSA root the reader pinned | any of those fails | no root pinned, no crypto backend, or an unread key type |

`genTime` is reported as read. It is the TSA's clock and is trusted only as
far as the pinned root is.

## The OTS sidecar rule

Every proof sits next to the bundle under the bundle's full file name plus a
suffix:

| file | holds |
|---|---|
| `BUNDLE` (for example `report.pdf.envelope.json`) | the envelope, one signature |
| `BUNDLE.ots` | the OpenTimestamps proof of the PAE digest |
| `BUNDLE.tsq` | the RFC 3161 request (it holds the nonce) |
| `BUNDLE.tsr` | the TSA reply |
| `BUNDLE.rekor.json` | the hashedrekord entry, then the log's answer |

The bundle writer (`write_bundle`) accepts only `mediaType` and
`dsseEnvelope{payloadType, payload, signatures[{keyid, sig}]}`. It refuses
any other key by name (`ots`, `timestampVerificationData`, `rekor`, and the
rest) and writes nothing. The reasons:

- An OTS proof grows after the fact (pending, then Bitcoin-attested). A proof
  inside the bundle would change the bundle's bytes after sealing.
- Sigstore's bundle has no field for OTS. Its Go and Python readers reject
  unknown fields, so a proof inside makes the whole file unreadable to them.

## Multi-witness: N bundles

A Sigstore bundle holds exactly one DSSE signature, and Sigstore clients
reject any other count. So "several witnesses" means several bundles:

- `split_witnesses(envelope)` returns one bundle per signature, in order, with
  the same payload. All of them anchor the same digest.
- `witness_bundle_path(file, keyid)` names each one
  `FILE.<12 hex of sha256(keyid)>.envelope.json`, so each witness gets its
  own sidecars.
- A key that signs twice, or a signature with no key id, is refused.

Each witness writes its own Rekor entry with its own key. Two witnesses are
two separate receipts. Neither one vouches for the other.

## How the verifier reads it

`read_anchors(bundle)` reads each sidecar on its own:

| anchor | sidecar absent | sidecar present |
|---|---|---|
| rekor | NOT CLAIMED | BROKEN if the entry names another digest or its signature fails; otherwise COULD NOT LOOK, because log inclusion is not checked yet |
| tsa | NOT CLAIMED | `check_tsa_token`'s verdict; COULD NOT LOOK without `BUNDLE.tsq`, because the nonce is unknown; BROKEN if the request asked for another digest |
| ots | NOT CLAIMED | COULD NOT LOOK in this skeleton |

There is no combined anchor verdict on purpose. One bad anchor does not hide
two good ones. The envelope's own verdict comes from `arcaeon envelope
verify` and never waits on any anchor. A reader who requires an anchor
decides what a COULD NOT LOOK on it means for them.

## The ARMED gate

- `ARMED = False` sits at the top of `rekor_anchor.py`. A test checks that it
  stays False and that the file never says `ARMED = True`.
- `submit()` is the only function that can reach the network; a test walks
  the module's syntax tree to check that. It refuses unless `ARMED` is True
  and the caller passes `i_have_his_go=True`. Either one alone sends nothing.
- A public log entry is permanent and public, and it is made under our key.
  Arming it is the owner's decision, not a code change made in passing. The
  TSA call, once built, sits behind the same gate.

## Migration from the statement-file pin

1. Keep the statement-file pin as it is. It anchors chain heads, which is a
   different thing from envelopes. Nothing about it changes here.
2. New envelopes get envelope anchors. Old envelopes have none and read NOT
   CLAIMED on every anchor, which is true.
3. If both kinds of entry ever share one witness key, the Rekor entries look
   alike (both are `hashedrekord` over a sha256). A reader tells them apart by
   which file the digest matches: a pin statement file or an envelope's PAE.
   A separate key per purpose would make that plain. This is open.
4. The witness pins repo is not touched by this plan.

## Build order

1. Done here: the offline skeleton with tests. That covers the digest, the
   entry shape, the offline entry check, the TSA request, the full offline
   token check against a pinned root, the sidecar names, the bundle guard,
   the witness split, the anchor reading and the refusing `submit`.
2. Choose the TSA (open, see below) and pin its root certificate in the repo
   as a public file.
3. Decide key custody for the witness key (open, see below). A test key is
   generated in memory; no real key exists in this work.
4. Build the armed TSA call (`tsa_submit`) behind the same gate, writing
   `BUNDLE.tsq` and `BUNDLE.tsr`.
5. Read Rekor v1's answer: store the entry UUID, log index, integrated time,
   signed entry timestamp and inclusion proof in `BUNDLE.rekor.json`. Then
   check inclusion offline against a pinned Rekor public key. Only then can
   the rekor anchor read VERIFIED.
6. Read `BUNDLE.ots` with the existing OTS check and fold it into
   `read_anchors`.
7. Add `arcaeon envelope anchors BUNDLE` (a read-only verb) and its docs.
8. Arm. That is the owner's call, made once per log and TSA.

## Open choices for the lead

- **TSA choice.** `timestamp.sigstore.dev` is what Sigstore verifiers already
  trust. FreeTSA is free but publishes no SLA or limits. A commercial TSA is
  another option. One TSA or two is also open.
- **Key custody.** Which key signs the Rekor entry (a dedicated P-256 witness
  key, or the sealer's key), where it lives, who can use it, and how it
  rotates. Rekor v2 takes only certificate or public-key verifiers. Whether
  Rekor v1 `hashedrekord` accepts an Ed25519 signature over a digest is not
  confirmed, so this plan uses P-256.
- **One key per purpose.** Whether chain-head pins and envelope anchors share
  a witness key (migration step 3).
- **A conformant Sigstore bundle.** If we later also write a Sigstore v0.3
  bundle, its `timestampVerificationData` may legally carry the RFC 3161
  token. Our own envelope bundle carries no proofs either way.
- **Public-instance volume.** The public Rekor terms ask for a "reasonable
  degree of use", and an open upstream issue asks whether non-software audit
  volume is welcome. Keep a self-hosted path in mind for partner volume.

## What it cannot prove

- An anchor proves that a digest was logged or stamped at or before some
  time. It does not prove the payload is true, or that the key belongs to
  whoever the label says.
- A Rekor entry under our witness key says that our witness saw the digest.
  It says nothing about the sealer beyond the envelope's own signature.
- A TSA token's time is only as good as the TSA and the root a reader pinned.
  The check follows at most two intermediate certificates carried in the
  token, and it does not check revocation or the ESS signing-certificate
  attribute.
- The rekor anchor cannot read VERIFIED until build step 5. Until then a good
  entry reads COULD NOT LOOK, never VERIFIED.
- The OTS anchor is not read by the skeleton. A present `.ots` reads COULD
  NOT LOOK.
- The public log is permanent and nothing put there can be removed. A digest
  hides its source only when the source cannot be guessed: anyone who can
  guess a short, predictable payload can confirm it against the log.
