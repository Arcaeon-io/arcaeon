# A2A extension: witness, version 1

Extension URI: `https://arcaeon.io/a2a/witness/v1`

This is the text meant for the page at that URI, the page a person or an
agent lands on when it dereferences the extension URI. It is kept here, in the
source repository, until it is hosted; this file does not say the URL is
live. The long form, with the specification sections it relies on quoted, is
[A2A.md](A2A.md). Where the two differ, the code
(`src/arcaeon/prove/a2a_receiver.py`) decides, and A2A.md is the one to fix.

## What it adds

When one agent hands another a file over the Agent2Agent protocol (A2A), this
extension carries a signed label for that file inside the A2A object that
carries it. The receiver checks the label against the file's bytes before it
acts, and gets one of three verdict words back: VERIFIED, BROKEN or COULD NOT
LOOK.

It adds no request or response flow, no endpoint and no method. It adds one
metadata value.

## The data

In the Artifact that carries the file (or the Message, when a client hands an
agent a file), under `metadata`, keyed by the extension URI:

```json
"extensions": ["https://arcaeon.io/a2a/witness/v1"],
"metadata": {"https://arcaeon.io/a2a/witness/v1": {"envelope": {...}}}
```

- The value is an object with exactly one key, `envelope`
  (`ENVELOPE_KEY = "envelope"` in the code).
- `envelope` is the labeled-exchange envelope, unchanged: the same JSON object
  `arcaeon envelope seal` writes as `FILE.envelope.json`. Its shape is in
  [ENVELOPE.md](ENVELOPE.md): `mediaType`
  `application/vnd.arcaeon.envelope.v1+json` and a `dsseEnvelope` (in-toto
  Statement, predicateType `https://arcaeon.io/labeled-exchange/v1`, Ed25519
  signature over the base64 payload).
- A key beside `envelope` is outside the signed payload. A receiver reads one
  as BROKEN.
- One envelope covers one file. A carrier with several files carries the
  envelope for the one file the receiver is meant to act on.
- The sender SHOULD list the URI in the carrier's `extensions` array. The
  listing is a hint; it is not signed and decides nothing.

File bytes are read from a `raw` part (A2A 1.0) or a `file.bytes` part (the
0.3 shape). A `url` part is never fetched by the reference receiver; whoever
fetches it passes the bytes in.

## AgentCard declaration and `params`

An agent that runs the check on what it is handed lists the extension under
`capabilities.extensions`:

```json
{"uri": "https://arcaeon.io/a2a/witness/v1", "required": false,
 "description": "Runs the arcaeon gate on an artifact's file before acting: ..."}
```

- `required` is optional for the extension and is the declaring agent's
  choice. The reference helper `agent_extension()` defaults it to `false`.
  `true` tells clients to send an envelope.
- `params` is not used in v1. An agent should leave it out; a receiver
  ignores it.

## Activation

Per the A2A extensions topic page (read 2026-10-05), extensions are inactive
by default, and a client asks for one by sending the `A2A-Extensions` header,
"a comma-separated list of extension URIs the client intends to activate".
The agent echoes the ones it activated in its own `A2A-Extensions` response
header. If an agent marks an extension `required: true` and the client does
not activate it, the agent "should reject the incoming request with an
appropriate error".

This extension adds one rule on top of that: activation does not change a
verdict. A receiver that declares the extension runs the check whether or not
the request activated it and whether or not the carrier lists it. The
reference receiver records both (`a2a.activated`, `a2a.listed`) and they
change nothing. An agent that sets `required: true` may still reject a request
that did not activate the extension, as the A2A rule allows; that is a
transport decision, separate from the verdict.

## Verdict words

The receiver hands the envelope and the file to the arcaeon gate, which
answers one word and allows or refuses the action the receiver is about to
take:

| verdict | read | act | pay | irreversible |
|---|---|---|---|---|
| VERIFIED | allow | allow | allow | allow |
| BROKEN | refuse | refuse | refuse | refuse |
| COULD NOT LOOK | allow | refuse | refuse | refuse |

- **VERIFIED**: the bytes are the ones a key the receiver named sealed, for
  this receiver's audience, and, for `act`, `pay` and `irreversible`, for the
  deal and purpose the receiver passed. Without a deal and purpose those three
  actions answer COULD NOT LOOK, so an envelope sealed for one exchange cannot
  be replayed into another.
- **BROKEN**: the bytes changed, the payload was edited, the signature does
  not check, it was sealed for another audience, deal or purpose, it expired,
  or a key sits beside `envelope`.
- **COULD NOT LOOK**: nothing wrong was found, but something needed was not
  there: no envelope (stripped or never sent), an envelope value that is not
  `{"envelope": {...}}`, no file bytes, several envelopes and none named, or
  A2A JSON that does not parse or has a duplicate key. It is never a pass;
  `read` only.

VERIFIED does not prove:

- that the content is true or safe (an allowed file can still be false, or
  carry a prompt injection);
- that the A2A sender is the sealer (the envelope names the sealing key; who
  sent the message is A2A's transport and authentication);
- anything about the rest of the message: other parts, other metadata, task
  state, the AgentCard;
- that the envelope was not replayed within its own audience, deal, purpose
  and validity window (a receiver that must act once keeps the envelopes it
  has acted on).

Removing the envelope turns an allow into COULD NOT LOOK, never into a false
allow.

## Version policy

The version is in the URI. `v1` keeps its data shape (one `envelope` key, the
envelope format named by its `mediaType`) and its verdict table. A change that
would make a v1 receiver misread a value, or allow what it refused, gets a new
URI (`/v2`), as the A2A extensions guidance asks: a breaking change gets a new
URI, and an agent MUST NOT fall back to a different version. [CHECK] whether
any non-breaking addition may ship under `v1` is not yet decided; until it
is, assume any change to the shape or the table gets a new URI.

This extension is published by arcaeon under its own URI. It is not
registered with, or governed by, the A2A project.

## Where the spec lives

- Source and reference receiver: https://github.com/Arcaeon-io/arcaeon
  [CHECK: confirm the repository is public before this page is hosted]
  (`src/arcaeon/prove/a2a_receiver.py`, command `arcaeon gate a2a`)
- Long form with the A2A sections quoted: `docs/A2A.md` in that repository
- The envelope: `docs/ENVELOPE.md`; the verdict words: `docs/WORDS.md`
- The A2A specification: https://a2a-protocol.org/latest/specification/ and
  the extensions topic, https://a2a-protocol.org/latest/topics/extensions/
