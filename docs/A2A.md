# The A2A witness extension

Extension URI: `https://arcaeon.io/a2a/witness/v1`

When one agent hands another a file over the Agent2Agent protocol (A2A), the
receiver has to decide whether to act on it. This extension carries the
labeled-exchange envelope ([ENVELOPE.md](ENVELOPE.md), predicateType
`https://arcaeon.io/labeled-exchange/v1`) inside the A2A object that carries
the file, so the receiver can run the gate before acting: VERIFIED, BROKEN or
COULD NOT LOOK, then allow or refuse.

It adds no new verifier and no new format. The envelope is the same JSON
object `arcaeon envelope seal` writes as `FILE.envelope.json`; the receiver
hands it to `arcaeon.prove.gate.decide`, which hands it to
`arcaeon.prove.envelope.verify`.

## What the A2A specification says (read 2026-10-04)

Sources read for this page:

- the specification, https://a2a-protocol.org/latest/specification/ (the
  latest release is 1.0.0, https://a2a-protocol.org/v1.0.0/specification/,
  with the same section numbers), and its source,
  `docs/specification.md` in https://github.com/a2aproject/A2A;
- the data model, `specification/a2a.proto` in the same repository, from
  which the specification's field tables are generated;
- the extensions topic page, `docs/topics/extensions.md` in the same
  repository (https://a2a-protocol.org/latest/topics/extensions/);
- for the older file part shape only, the 0.3.0 specification,
  https://a2a-protocol.org/v0.3.0/specification/ (6.6 FilePart, 6.6.1
  FileWithBytes, 6.6.2 FileWithUri).

What this extension relies on, by section:

- **3.2.5. Metadata.** "A flexible key-value map for passing additional
  context or parameters with operations. Metadata keys must be strings, and
  values can be any valid JSON value. Extensions can be used to strongly type
  metadata values for specific use cases."
- **4.1.7. Artifact.** Fields `artifactId` (required), `name`,
  `description`, `parts` (required, at least one), `metadata` ("Optional.
  Metadata included with the artifact.") and `extensions` ("The URIs of
  extensions that are present or contributed to this Artifact."). **4.1.4.
  Message** has the same `metadata` and `extensions` pair.
- **4.1.6. Part.** One of `text`, `raw` (file bytes, base64 in JSON), `url`
  or `data`, plus `metadata`, `filename` and `mediaType`. (Version 0.3.0 used
  `{"kind": "file", "file": {"bytes" | "uri", "name", "mimeType"}}`; the
  reference receiver reads both.)
- **4.6. Extensions; 4.6.1. Extension Declaration.** Agents declare the
  extensions they support in the AgentCard under
  `capabilities.extensions`, an array of AgentExtension (**4.4.4**: `uri`,
  `description`, `required`, `params`). Clients opt in per request "through
  binding-specific mechanisms such as HTTP headers, gRPC metadata, or
  JSON-RPC request parameters".
- **4.6.2. Extensions Points.** "Artifacts can include extension data to
  provide strongly typed context or metadata about the generated content."
  The example puts the extension's object in the artifact's `metadata` under
  the extension URI as the key, and lists the URI in `extensions`. This is
  the shape used here.
- **4.6.3. Extension Versioning and Compatibility.** The URI SHOULD carry
  the version; a breaking change MUST get a new URI; an agent MUST NOT fall
  back to an earlier version of an extension.
- **3.2.6 Service Parameters; 14.2.2. A2A-Extensions Header.** On HTTP,
  `A2A-Extensions` is "a comma-separated list of extension URIs that the
  client wants to use for the request".
- **Extensions topic page, "Extension Activation".** "Extensions default to
  being inactive." The client asks for activation with the `A2A-Extensions`
  header; the agent activates the ones it supports and SHOULD echo them in
  the response header. "Required Extensions": an agent that marks one
  `required: true` should reject a request that does not activate it. The
  "Security" list says extension data from another party is untrusted input.

So the specification separates three things: an agent **declaring** support
(its AgentCard), a request **activating** it (the header), and an object
**listing** it as present (`extensions` on the Artifact or Message). None of
the three is signed by the sender of the file.

## The extension

### Where the envelope rides

In the Artifact that carries the file (or the Message, when a client hands an
agent a file), under `metadata`, keyed by the extension URI, holding one
object with one key, `envelope`:

```json
{
 "artifactId": "grades-001",
 "name": "week 3 grades",
 "parts": [{"raw": "<base64 of the file>", "filename": "grades.csv", "mediaType": "text/csv"}],
 "extensions": ["https://arcaeon.io/a2a/witness/v1"],
 "metadata": {
  "https://arcaeon.io/a2a/witness/v1": {
   "envelope": {
    "mediaType": "application/vnd.arcaeon.envelope.v1+json",
    "dsseEnvelope": {
     "payloadType": "application/vnd.in-toto+json",
     "payload": "<base64 of the Statement>",
     "signatures": [{"keyid": "did:key:z6Mk...", "sig": "<base64 Ed25519 signature>"}]
    }
   }
  }
 }
}
```

- `envelope` is the sidecar object, unchanged. Its signature is over the
  base64 payload, so an A2A layer that re-serializes the JSON around it does
  not disturb the check.
- **No other key sits beside `envelope`.** A key there is outside the signed
  payload and could say anything; the receiver reads one as BROKEN, the same
  as a stray key in a sidecar.
- One envelope covers one file (the Statement names exactly one subject). An
  artifact that carries several files carries one envelope for the one file
  the receiver is meant to act on; the receiver is told which bytes to check.
- The sender SHOULD list the URI in the carrier's `extensions`.

### Declaring it

An agent that runs the gate on what it is handed lists the extension in its
AgentCard:

```json
"capabilities": {
 "extensions": [
  {"uri": "https://arcaeon.io/a2a/witness/v1", "required": false,
   "description": "Runs the arcaeon gate on an artifact's file before acting."}
 ]
}
```

`required` is the agent's choice: `true` tells clients to send an envelope
(and, by the specification's rule, lets the agent reject a request that does
not activate the extension). `params` is not used in v1.

### The receiver's rule

**A receiver that declares this extension MUST run the gate before acting on
an artifact's file**, with its own audience id, the signer keys it trusts,
and the action it is about to take, and MUST follow the gate's table:

| verdict | read | act | pay | irreversible |
|---|---|---|---|---|
| VERIFIED | allow | allow | allow | allow |
| BROKEN | refuse | refuse | refuse | refuse |
| COULD NOT LOOK | allow | refuse | refuse | refuse |

It MUST run the gate whether or not the request activated the extension and
whether or not the artifact lists it. Activation and listing are unsigned:
they decide nothing. Not activated, with no envelope, is COULD NOT LOOK and
read only, the same as activated with no envelope; a listing cannot make a
missing envelope good, and its absence cannot make a good one bad.

What each case reads:

| what arrives | verdict | why |
|---|---|---|
| a good envelope, the bytes it sealed, your audience, a key you named | VERIFIED | |
| nothing under `metadata[URI]` (stripped, or never sent) | COULD NOT LOOK (`missing`) | nothing says what the file is or who sealed it |
| `metadata[URI]` that is not `{"envelope": {...}}` | COULD NOT LOOK (`unreadable`) | |
| no file bytes to check (a `url` part only; the receiver never fetches) | COULD NOT LOOK (`missing`) | |
| several carriers with an envelope and none named | COULD NOT LOOK (`bounded`) | which file is meant is not known |
| A2A JSON that does not parse, a duplicate key anywhere | COULD NOT LOOK (`unreadable`) | two readers would see two messages |
| changed file bytes, an edited payload, a bad signature | BROKEN | |
| sealed for another audience, deal or purpose; expired | BROKEN | |
| a key beside `envelope` | BROKEN | outside the signed payload |
| everything else | what `envelope verify` answers | see ENVELOPE.md |

Field names follow the envelope's naming: the key is `envelope`, never
`bundle`; nothing in this extension is a flag word.

## The reference receiver

`arcaeon.prove.a2a_receiver` (standard library only; signature checks load
the `[sign]` extra as `envelope verify` does):

```python
from arcaeon.prove import a2a_receiver as A

d = A.receive(message_bytes, file_bytes, action="pay", audience="instructor-1",
              signers=["did:key:z6Mk..."], deal="d-7f3a", purpose="grading",
              ledger="my-deal-tape.jsonl", activated=request_headers.get("A2A-Extensions"))
d.decision      # "allow" or "refuse"
d.verdict       # VERIFIED, BROKEN or COULD NOT LOOK
d.a2a           # extension, carrier, id, listed, activated, file_from
```

- `message` is the A2A JSON as bytes (parsed strictly) or a dict: an
  Artifact, a Message, a Task (its `artifacts`; never its `history`), a
  TaskArtifactUpdateEvent, or a JSON-RPC request or response around one.
- `file` is the artifact's file as bytes or a path. Left out, the bytes come
  from the carrier's one inline `raw` part; a `url` part is never fetched.
- `artifact_id` picks the carrier when several hold an envelope.
- On BROKEN with a deal id, the gate's evidence pack also keeps the A2A
  message as `bundle/a2a-message.json`, and `evidence.json` gains an `a2a`
  object with its sha256.
- It raises only on an unknown action. A hostile message is an answer, never
  a traceback, and never an allow beyond `read`.

`A.attach_envelope(artifact, envelope)` is the sender's side;
`A.agent_extension()` is the AgentCard entry; `A.declares(card)` checks one.

On the command line:

```console
$ arcaeon gate a2a --message task.json --file grades.csv --audience instructor-1 --signer did:key:z6Mk... --action pay --deal d-7f3a --purpose grading --ledger my-deal-tape.jsonl
allow pay: VERIFIED. The bytes are unchanged since the key you named sealed them, ...
```

Exit codes as `gate decide`: 0 allow, 1 refuse (BROKEN), 3 refuse (COULD NOT
LOOK), 2 bad usage.

## What it does not prove

Everything in ENVELOPE.md's "What VERIFIED does not prove" holds here, and:

- **That the content is true or safe.** An allowed file can still be false,
  or carry a prompt injection.
- **That the A2A sender is the sealer.** The envelope names the key that
  sealed the bytes; which agent sent the A2A message is A2A's transport and
  authentication, not this check. A relaying agent can forward a genuine
  sealed file, and inside its binding that is allowed.
- **Anything about the rest of the message.** The text parts, the other
  parts, the other metadata, the task state and the AgentCard are not
  covered. Only the one file's bytes and the envelope's own fields are.
- **That the extension was activated or listed.** Those are recorded under
  `a2a` and change nothing.
- **That a `url` part points at the sealed bytes.** The receiver does not
  fetch; whoever fetches passes the bytes, and the check is on those bytes.
- **That nobody stripped the envelope.** Anyone on the path can remove the
  metadata. That turns an allow into COULD NOT LOOK (read only), never into
  a false allow.
- **That it was not replayed within its binding.** The same artifact can be
  sent twice inside one audience, deal, purpose and validity window. A
  receiver that must act once keeps the envelopes it has acted on.
- **That this is an A2A-registered extension.** It is published by arcaeon
  under its own URI, outside the `https://a2a-protocol.org/extensions/`
  namespace the A2A organization governs.
