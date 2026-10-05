# Account as ID: agent keys under a human owner (design + stub)

Status: a design and a reference stub (`arcaeon.prove.account_id`), not a
service. No hosted endpoint runs today, no CLI verb of its own (the exchange
and tally verbs read its store with `--accounts`), no network, no real keys.

The ID is the arcaeon.io account. A person signs up on the site (that step is
the existing site signup and is out of scope here). That person, the
**owner**, then issues keys for agents by an API call. An agent never clicks
sign-up and never issues a key for itself. An identity an agent already has
(Microsoft Entra Agent ID, Okta, AWS STS, SPIFFE, Sigstore) is **bound** to
the account as a receipt; it is never a rival ID. Agents with no tenant use
the plain `did:key` path, which stays.

## Names

| thing | form | example |
|---|---|---|
| owner account | `acct:OWNER@arcaeon.io`, OWNER one label | `acct:owner-a@arcaeon.io` |
| agent account | `acct:AGENT.OWNER@arcaeon.io`, AGENT one label | `acct:bot1.owner-a@arcaeon.io` |
| agent key | Ed25519 `did:key` (56 characters) | `did:key:z6Mk...` |
| server binding key | Ed25519 `did:key`, published by arcaeon.io | `did:key:z6Mk...` |

The account grammar is the one in `exchange_log.py` (`ACCOUNT_ID_RE`, at most
64 characters of name). Putting the owner inside the agent's account name
means an agent's possession proof cannot be replayed under another owner: the
proof names the account, and the account names the owner.

## Where the agent's private key is made

**On the agent's side.** The agent generates its own Ed25519 seed and sends
only a possession proof: an `exchange.binding` row (docs/EXCHANGE.md) that
its key signs, naming its own agent account. The server checks that proof and
signs a binding row over it. The server never sees or holds an agent private
key, so a server breach cannot sign as an agent. (A "server generates and
returns the key" convenience path is not offered; see the open questions.)

## Auth model

| caller | may |
|---|---|
| owner session (the site login) | issue, list, rotate, revoke, attach, read full receipts |
| owner API key (made by the owner on the site) | issue, list, rotate, revoke, attach, read full receipts |
| agent key | nothing on this API: 403. An agent never self-issues |
| anyone, no auth | fetch the public binding statement for a did:key (no IdP `sub`) |

The stub takes the caller as already authenticated by the site's auth layer
(`{"kind": "owner_session" | "owner_api_key", "owner": ...}`); checking
sessions and owner API keys is the site's job, not this module's. An owner
sees and acts on only its own agents; anything else answers 404 (not 403, so
account names under other owners are not probed).

## Endpoints

All bodies are JSON. Errors are `{"error": "one sentence"}` with the status.

### Issue an agent key: `POST /v1/agents` (owner)

Request:

```json
{"agent": "bot1",
 "proof": {"kind": "exchange.binding", "v": 1,
           "account": "acct:bot1.owner-a@arcaeon.io",
           "at": "2026-10-05T12:00:00Z",
           "signer": "did:key:z6Mk...agent",
           "sig": "base64..."}}
```

`proof` is what `possession_proof(seed, account)` (or `arcaeon exchange bind`)
makes on the agent's machine. It must be at most 15 minutes old.

Response `201`:

```json
{"binding": {"kind": "account.binding", "v": 1, "event": "issue",
             "account": "acct:bot1.owner-a@arcaeon.io",
             "owner": "acct:owner-a@arcaeon.io",
             "key": "did:key:z6Mk...agent", "prev": null,
             "at": "2026-10-05T12:00:00Z",
             "signer": "did:key:z6Mk...server",
             "agent_proof": {"...": "the proof above, verbatim"},
             "external": null, "reason": null, "sig": "base64..."}}
```

Refusals: 401 no owner, 403 agent key, 400 bad name or proof (bad signature,
another account, stale, an oversized did:key refused before decoding), 409
account exists or key already bound, 429 over the per-owner cap.

**Duplicate issue (decided: idempotent on an exact repeat, refused
otherwise).** The same owner sending the same agent name with the same proof
while that key is active gets the existing row back (`200`) and nothing is
written. The same name with another key is 409 (a new key on an existing
account is a rotate). A key that was ever bound anywhere is 409: a key is
bound once.

### List the owner's agents: `GET /v1/agents` (owner)

```json
{"agents": [{"account": "acct:bot1.owner-a@arcaeon.io",
             "owner": "acct:owner-a@arcaeon.io",
             "key": "did:key:z6Mk...", "status": "active",
             "bound_at": "2026-10-05T12:00:00Z", "revoked_at": null,
             "history": 1}]}
```

### Revoke: `POST /v1/agents/{account}/revoke` (owner)

Request `{"reason": "key lost"}` (optional, one line). Response `200`
`{"binding": {... "event": "revoke", "key": the revoked did:key, "reason": ...}}`.
409 if the account has no active key, or if the request time is before
the account's last row (see "Row times never go backwards" below). The
account and its history stay.

### Rotate: `POST /v1/agents/{account}/rotate` (owner)

Request `{"proof": <a fresh possession proof by the NEW key for the same
account>}`. Response `200` `{"binding": {... "event": "rotate", "key": new,
"prev": digest of the previous row}}`. The old key, if still active, is
retired at the rotate row's time. Rotate also works after a revoke: that is
how an owner recovers an account whose key was lost or stolen. **The new key
inherits the record** (TE-44d): the tally keys on the account, and the
account's history is one hash-linked list that cannot be reset. Re-issuing a
revoked account's name is 409.

**Row times never go backwards.** Rotate, revoke and attach are refused with
409, and nothing is written, when their time is before the account's last
row. The verifier calls a history BROKEN when row i is dated before row
i-1, and the history cannot be reset, so one backdated row would read every
pairing on the account BROKEN at every time. An equal time (the same second)
is allowed, as the verifier allows it.

### Fetch the public binding statement: `GET /v1/keys/{did}/binding` (anyone)

```json
{"type": "https://arcaeon.io/account-binding-statement/v1",
 "did": "did:key:z6Mk...",
 "account": "acct:bot1.owner-a@arcaeon.io",
 "owner": "acct:owner-a@arcaeon.io",
 "rows": [ {"event": "issue", "...": "..."}, {"event": "rotate", "...": "..."} ]}
```

`rows` is the whole account history, not only the rows about this key, so a
reader sees rotations and revocations. 404 for a key never bound. The
top-level `account` and `owner` are a convenience; the verifier reads the
rows and calls a disagreement BROKEN.

**No IdP `sub` in the public view.** An external row carries the receipt's
`iss` and `sub_sha256`, never `sub` (an Okta `sub` can be an email address).
`sub_sha256` is `sha256(salt || sub)` with a fresh 16-byte random salt per
receipt that stays owner-only. Salted, not plain, because a plain sha256 of
an email is undone by guessing addresses, and the same `sub` on two
accounts would publish the link between them. The hash is inside the signed
row, so the public statement verifies as it is; the owner can open it by
showing `sub` and the salt.

### Read the full receipts: `GET /v1/agents/{account}/binding` (owner)

The same signed history as the public statement, plus `receipts`: one
`{"row": INDEX, "receipt": {... "sub": ...}, "sub_salt": "32 hex"}` per
external row, where `sha256(bytes.fromhex(sub_salt) + sub)` is that row's
`sub_sha256`. 401 no owner, 403 agent key, 404 not this owner's account.

### Attach an external identity: `POST /v1/agents/{account}/external` (owner)

The IdP token (an Entra access token with `aud` = arcaeon, an Okta ID-JAG or
DPoP-bound token, an AWS STS `GetWebIdentityToken` JWT, a SPIFFE JWT-SVID) is
checked **online, upstream of this stub**: issuer allow-list resolved before
the signature, JWKS, `aud`, `exp`, agent facets (R10). What reaches the
account is a receipt, and **the token itself is never stored**:

```json
{"receipt": {"issuer_family": "entra",
             "iss": "https://sts.windows.net/TENANT/",
             "sub": "agent-object-id", "facets": ["11"],
             "key_jkt": null,
             "jwt_sha256": "64 hex", "jwk_sha256": "64 hex",
             "binding_strength": "possession-sig",
             "checked_at": "2026-10-05T12:30:00Z"}}
```

`binding_strength` is `idp-cnf` (the IdP signed our key's thumbprint: Okta
DPoP `cnf.jkt`, Entra mTLS-PoP `cnf`), `idp-tag` (an STS tag carries it) or
`possession-sig` (only the agent's own signature tied token and key).
`idp-cnf` and `idp-tag` need `key_jkt`, the RFC 7638 thumbprint of the
active key (`jwk_thumbprint(did)`), and it must match. Any field outside this
shape (`id_token`, `access_token`, `jwt`, `token`) is refused with 400, so a
live bearer token cannot be written by mistake. Response `201` with an
`event: "external"` row whose `external` holds the receipt with `sub`
replaced by `sub_sha256` (see the public statement above) (409 if the account has no active key or the time
is before its last row). Public Sigstore Fulcio takes no Entra or Okta token
today (R10), so `sigstore` here means a Sigstore identity the agent already
holds, bound the same way.

## The binding row

Kind `account.binding`, v `1`. Every field is signed; unused ones are null.

| field | what |
|---|---|
| `kind`, `v` | `account.binding`, `1` |
| `event` | `issue`, `rotate`, `revoke`, `external` |
| `account` | the agent account |
| `owner` | the owner account |
| `key` | issue/rotate: the key bound; revoke: the key revoked; external: the active key |
| `prev` | null on the first row; else `sha256:json-c14n:v1:` digest of the previous row (signed fields + sig) |
| `at` | UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `signer` | the server binding key |
| `agent_proof` | issue/rotate: the agent's `exchange.binding` row, verbatim |
| `external` | external: the receipt with `sub` replaced by `sub_sha256` (salted; the full receipt is owner-only) |
| `reason` | revoke: optional text |
| `sig` | base64 Ed25519 over `PAE("application/vnd.arcaeon.account.binding.v1+json", C)`, `C` the json-c14n v1 bytes of the signed fields |

**Where it reuses `exchange.binding`.** The same account grammar, the same
UTC time form, the same PAE + json-c14n signing, the same "sig outside, every
other field signed" rule, and the agent's possession proof IS an
`exchange.binding` row, checked by `exchange_log.check_binding`.

**Where it differs.** An `exchange.binding` row is the key holder's own
claim ("this key says it is acct:X"); EXCHANGE.md says arcaeon.io's agreement
is not checked there. An `account.binding` row is arcaeon.io's claim, signed
by the server key, that the account and its owner hold that key, wrapping the
agent's own claim. It also carries an owner, an event, and a `prev` link, so
an account has one history across keys, which the exchange row does not.

## Verify paths and their three words

`verify_binding(statement, did, server_keys=[...], at=WHEN)`: "was this
did:key bound to its account at WHEN?" (WHEN defaults to now: the verifier's
own clock.) Never raises.

| path | VERIFIED | BROKEN | COULD NOT LOOK |
|---|---|---|---|
| key to account | every row signed by a server key you named, the `prev` links hold, every agent proof checks, the key was bound at WHEN | a row's signature fails; a `prev` link fails (a row dropped, moved, changed); an agent proof fails or names another key; rows signed by a key you did not name; the statement's top-level account or owner differs from its rows | no statement (unknown key); a statement that does not bind this key; a key that is not an Ed25519 did:key (length checked before any decode); no trusted server key named; no Ed25519 backend |
| an envelope sealed at T | T is at or after the key was bound and before it was revoked or rotated out; a later revocation is shown (`revoked_at`) beside the VERIFIED | T is at or after the revoke or rotate | T is before the key was bound: the account did not hold it then |
| an external receipt | the receipt row is server-signed in an unbroken history and its `key_jkt`, when present, is the bound key's thumbprint | `key_jkt` does not match the key the row names | (the IdP's own signature is not re-checked offline; the raw token is not kept; see below) |

Revocation: revoked at T means envelopes sealed at or after T read BROKEN,
and envelopes sealed before T stay as they were, VERIFIED, with the
revocation shown beside them. A rotation retires the old key the same way.

### The exchange pairing, held to the account service (L3-02)

`arcaeon exchange pair` and `arcaeon tally build` take `--accounts FILE
--account-key DID` (library: `accounts=`, `account_keys=`). FILE is a store
in the stub's own shape or `{"statements": [...]}` of public binding
statements; the trusted binding key comes only from `--account-key`. Each
`exchange.binding` row that pairs an account id is checked with
`consult_binding(service, did, account, rows)`, which calls
`verify_binding` at the row's `at` and then requires the statement's
account to be the one the row claims: VERIFIED stands, BROKEN (revoked or
rotated out by then, another owner, another account, a forged or untrusted
service row) and COULD NOT LOOK (no record, no trusted key) drop the
pairing. A row that is the agent's possession proof wrapped by an issue or
rotate row is read at that row's time (the proof is signed minutes before
the issue). Without `--accounts`, nothing changes and the pair report says
"account service not consulted". Tables: docs/EXCHANGE.md, docs/TALLY.md.

**Freshness: a statement is as fresh as its fetch; a revocation after
`fetched_at` is not seen.** A FILE is a replay of what the service said
when it was fetched, so the report's `account_service` block carries
`fetched_at` and its reason says "as of <time>". `fetched_at` is a top-level
`"fetched_at": "YYYY-MM-DDTHH:MM:SSZ"` in FILE if the fetcher wrote one, else
FILE's modification time; when both are there the older one is used (a
statement is never claimed fresher than either says). A `fetched_at` that is
not a UTC time refuses the file. A live in-memory store is read at load time;
in-memory statements with no time say "as of an unknown time". Fetch again
before relying on a pairing near or after a key's possible revocation.

## Rate and Sybil notes

- **Keys per owner.** At most `MAX_AGENTS_PER_OWNER` agent accounts per owner
  (100 in the stub; a placeholder, not a decision). Revoked accounts count,
  so churning accounts does not reset the cap. One active key per account.
- **Control cluster.** `control_cluster()` returns the owner account. It is
  the minimum cluster: the tally counts trades between two agents of one
  owner as self-trades (TE-44a). R11 says a cluster should also merge shared
  funding, shared billing and shared register entries; that wider merge needs
  billing data this stub does not have, and the tally should print the
  cluster-adjusted counts beside the raw ones, not silently.
- **Issue rate.** The hosted API should also rate-limit issue calls per owner
  and per IP; the stub does not.
- **Price.** Not set here. R22's credit unit (1 credit = $0.001) is the
  reference if a key or a binding row is ever priced; verifying a binding
  costs nothing and runs offline.

## What this cannot prove

A VERIFIED binding says arcaeon.io signed that the owner's account held that
key over a span of time. It cannot place a signature inside that span when
the time comes from the signer. Worked example:

1. On 10/5 an owner issues `acct:bot1.owner-a@arcaeon.io` with key K.
2. On 10/9 K is stolen. On 10/10 the owner revokes K (T = 10/10 09:00Z).
3. On 10/12 the thief seals an envelope with K and writes `sealed_at` =
   10/8, a time inside K's live span.
4. A receiver verifies the binding at 10/8 and gets VERIFIED, with
   `revoked_at` 10/10 shown beside it.
5. Nothing in the binding can tell this from an honest 10/8 seal: the seal
   time is the signer's own word. Only an outside clock on the envelope (a
   witness pin, OpenTimestamps or Rekor, dated before T) separates them; an
   envelope with no outside time sealed by a revoked key should be read as
   doubtful even when the binding says VERIFIED.

Also outside what a binding proves: that the owner is who the account name
suggests; that the agent behaves; that an external identity is still alive or
unrevoked at its IdP now (a receipt says "bound at T", never "currently
authorized"); and anything about arcaeon.io itself. The rows are signed by
our key, so until they are witnessed outside our control (a pinned chain, as
for the tally), they are arcaeon.io's word.

## Open questions for the owner of this design

- Agent-side key generation only, or also a server-generates convenience
  path (it would mean the server once held the key)?
- `acct:AGENT.OWNER@arcaeon.io` as the agent account form, with owner names a
  single label?
- The per-owner cap and any price per key or per binding row.
- Owner transfer (moving an agent to another owner) is not designed; today
  the owner on every row must match.
