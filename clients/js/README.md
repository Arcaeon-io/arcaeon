# arcaeon JavaScript client

One file, `arcaeon.mjs`, no packages. It calls a running `arcaeon serve`
(loopback, `127.0.0.1`) with `fetch`, so it works in Node 18+, Deno and Bun.

```js
import { Client } from "./arcaeon.mjs";

const c = await Client.connect();   // url from serve.json, token from serve.token
const r = await c.verify({ ledger: "calls.jsonl" });
console.log(r.verdict, r.exit);     // VERIFIED 0
```

`Client.connect()` reads `serve.json` and `serve.token` from `ARCAEON_HOME`
(default `~/.arcaeon`), the files `arcaeon serve` writes. In a browser, or to
talk to a server you started elsewhere, pass them yourself:
`new Client({ url: "http://127.0.0.1:8787", token })`. The client never
creates a token and never prints one.

## Methods

One per route, taking the request body as an object: `health`, `openapi`,
`log`, `verify`, `reconcile`, `auditVerify`, `auditExport`, `receiptVerify`,
`status`, `pin`, `seal`, `evidencePack`, `evidencePackVerify`, `exportAat`,
`mandateCheck`, `readings`, `secondReadCompare`, `handshakePropose`,
`handshakeAccept`, `handshakeVerify`. `call(method, path, body)` reaches any
route by path. The request fields are in `GET /openapi.json`.

## What comes back

Every method resolves to the server's JSON; none rejects.

- A verdict (VERIFIED, BROKEN, MATCHED, COULD NOT LOOK) comes back with its
  integer `exit`: 0 nothing wrong found, 1 something wrong found, 3 could not
  look. Branch on `exit`, never on the HTTP status.
- A refusal the server sent (bad request, no token, no such route, body over
  10 MB) comes back as its body plus `http_status`, and its `exit` is never 0.
- A server that cannot be reached is `COULD NOT LOOK`, exit 3,
  `reason_word: "network"`. A reply that is not JSON is `COULD NOT LOOK`,
  `reason_word: "unreadable"`. Neither is ever a pass.

## Test

```
node --test clients/js/arcaeon.test.mjs
```

The test starts `python -m arcaeon serve --port 0` against a temporary
directory (the `py` launcher on Windows, `python3` elsewhere, or
`ARCAEON_PYTHON`), reads the url it prints, checks a fixture ledger, and
stops the server.
