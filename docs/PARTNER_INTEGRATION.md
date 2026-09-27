# Partner integration: pin a customer's trace head, hand them an evidence pack

Your customers already trust your traces. Who checks them?

Today the answer is usually nobody but you. The traces live on your systems,
the dashboard that shows them is yours, and when a customer disputes what
their agent did, the only copy of the story is the one you kept. This page is
for observability and agent-platform vendors who want to hand a customer
something they can check without taking your word for it: the head of the
customer's trace ledger, pinned, and an evidence pack the customer verifies on
their own machine.

It came out of a 911 dispatch floor, where the CAD timeline and the recording
exist so that nobody on the floor is the only copy of the story. Same idea,
aimed at agent traces.

Every example below is run by the test suite (`tests/test_docs.py`) against a
local `arcaeon serve` it starts on `127.0.0.1`, with no network. `arcaeon serve`
and the evidence pack come with the next release of the package.

## Before any example

    arcaeon serve --root ./served

- The server binds `127.0.0.1` only. Putting it on a network is your deploy
  decision, not something it does for you.
- Every `/v1` route needs the token in `serve.token` (created on first run),
  sent as `Authorization: Bearer <token>`.
- Every path in a request body is resolved under `--root`. A path that climbs
  out of it is refused.
- A verdict never rides in the HTTP status. Every answer below is HTTP 200
  with the verdict and an integer `exit` in the body: 0 good, 1 a bad finding,
  2 bad usage, 3 COULD NOT LOOK (never a pass).

## 1. Write the customer's traces as a ledger

If your traces are not already an arcaeon ledger, append each one as a row.
Each row is hash-chained to the row before it.

```http
POST /v1/log
{"ledger": "customer-a.jsonl", "fields": {"ts": "2026-09-01T10:00:00Z", "agent": "support-bot", "event": "tool_call", "inputs": {"q": "order 1182"}}}
```

```json
{"exit": 0}
```

```http
POST /v1/log
{"ledger": "customer-a.jsonl", "fields": {"ts": "2026-09-01T10:05:00Z", "agent": "support-bot", "event": "decision", "decision": "refund"}}
```

```json
{"exit": 0}
```

## 2. Pin the head

A pin records the ledger's row count and chain value, as of now, in a witness
file.

```http
POST /v1/pin
{"ledger": "customer-a.jsonl", "witness": "witness.jsonl", "ns": "customer-a"}
```

```json
{"ok": true, "exit": 0, "namespace": "customer-a", "pin": {"rows": 2}}
```

A local pin is a line in a file you hold. It starts to mean something once a
copy leaves your hands: send the customer `witness.jsonl` each time you pin,
not only when they ask for a pack. A pin file only you ever held is one you
could rewrite along with the ledger.

## 3. Build the pack for one agent and one window

```http
POST /v1/evidence-pack
{"ledger": "customer-a.jsonl", "out": "pack", "agent": "support-bot", "witness": "witness.jsonl", "namespace": "customer-a", "built_at": "2026-09-27T12:00:00Z"}
```

```json
{"verdict": "VERIFIED", "exit": 0, "finding": "PASS", "window": {"agent": "support-bot", "rows": 2}}
```

The pack folder holds the window's rows, the full records they came from,
the pins, a `manifest.json` with every file's hash, the `manifest.sha256`
sidecar, `could_not_look.json` (what the build could not check, never
hidden) and a `README.md` for whoever opens it. `"zip": true` also writes
`pack.zip`; with `built_at` set, the same inputs give the same zip bytes.

You can check it before you send it:

```http
POST /v1/evidence-pack/verify
{"pack": "pack", "witness": "witness.jsonl", "namespace": "customer-a"}
```

```json
{"verdict": "VERIFIED", "exit": 0}
```

## 4. The customer checks it on their own machine

The customer needs the package, the pack, and their own copy of the pin file.
Nothing here talks to you or to us.

```console
$ arcaeon evidence-pack verify pack --witness witness.jsonl --namespace customer-a
VERIFIED: evidence pack pack
```

## 5. Show it break

Change one byte of one row in the pack and check again:

```console
$ python -c "p='pack/records.jsonl'; b=open(p,'rb').read(); i=b.index(b'refund'); open(p,'wb').write(b[:i]+b'R'+b[i+1:])"
$ arcaeon evidence-pack verify pack --witness witness.jsonl --namespace customer-a
BROKEN: evidence pack pack (file hashes: sha256 differs from the manifest: records.jsonl; records chain and head: records.jsonl chain breaks at line 2: chain mismatch; window rows equal their records lines: window.jsonl rows differ from records.jsonl at ledger line 2)
  COULD NOT LOOK [bounded] re-derived fields and prose: records.jsonl fails its own hash or chain, so integrity.json, README.md and ARTICLE_12_SUMMARY.md were not re-derived from it
(exit 1)
```

The verify also catches a forged file added to the pack, a pin stripped out
of it, and a manifest rewritten to match edited rows (the sidecar no longer
agrees).

## The paid lane: a remote pin

`/v1/pin` with `"remote": true` pins the head with the hosted witness at
`witness.arcaeon.io` instead of a local file. That is the paid lane, and it
spends only with two opt-ins: `ARCAEON_KEY` set, and the server started with
`arcaeon serve --allow-paid`. The flag is read from the server, never from the
request, so an agent cannot grant itself the spend. Without them nothing is
sent and the answer is a refusal:

```http
POST /v1/pin
{"ledger": "customer-a.jsonl", "remote": true, "ns": "customer-a"}
```

```json
{"verdict": "COULD NOT LOOK", "exit": 3, "refused": true}
```

A refusal is COULD NOT LOOK, never green. Prices for the hosted pins are on
https://arcaeon.io/pricing, not here.

## What it does not prove

- **What happened.** The chain records whatever was written, true or not. A
  pack shows the rows are the rows that were pinned, not that the rows
  describe what the agent really did.
- **Anything after the last pin.** Cut the most recent rows off and what is
  left still checks out. A pin closes that only as of the moment it was taken;
  the gap between pins is how much you could lose without anyone noticing.
- **Who wrote a row.** Authorship is data in the row, not a signature.
- **A second party, by itself.** A local pin file you alone hold is not a
  witness. The hosted witness is one witness, which we operate; it is a party
  you cannot advance, not a group of strangers.
- **Anything about law.** A pack is evidence toward record-keeping duties a
  customer may have; it does not make anyone meet one.
