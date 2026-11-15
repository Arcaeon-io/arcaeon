# What the join changes in `arcaeon buy` and in arcaeon's keys

A line by line map, read only: every line of `arcaeon buy` and of arcaeon's
key handling that would change if arcaeon follows docs/JOIN_CLIENT.md (pull
request 15), which follows the witness sandbox's docs/JOIN_SPEC.md (sandbox
pull request 64, at `71ff6cf`). Nothing here is changed yet.

**Where the line numbers point.** At commit `7800e4c`, the head of the
branch of pull request 11, which holds pull requests 7, 11 and 14: the newest
state of `buy`. Pull requests 8, 9 and 12 reword some of the same README and
docs lines; where they do, the row says so.

**What "key-id" means here.** arcaeon has no `key-id` command. The name is
the `--witness-key-id` option of the seal and of the desktop's witness client:
the key id of the one witness a client trusts. arcaeon has no such value
today. So the key rows below cover everything in arcaeon that decides which
key is used, what a key is told it is for, and which witness a key is sent
to: `ARCAEON_KEY`, the namespace prefix learned from it, and the witness
address.

Each row: the file and line, what is there now, and what the spec makes it.
"JC" is docs/JOIN_CLIENT.md, "JS" the server spec.

## 1. `arcaeon buy`

| File and line | Now | Under the spec |
|---|---|---|
| `src/arcaeon/remote/catalog.py:294` | `Free: {free:,} pins a month on the hosted witness.` | The one free allowance line of JC 8: `Free: <N> pins a month for each key, no purchase needed; the count starts again on the first of the month (UTC).` The allowance is per signing key (JS 9), so "on the hosted witness" no longer says who it is for. |
| `src/arcaeon/remote/catalog.py:276-281` | Falls back to the words "N free pins a month" in the hosted witness description when the list has no number field. | Removed. JC 8 reads the number only from the structured field; with no field, no line. |
| `src/arcaeon/remote/catalog.py:267-275` | Looks for `free_pins_per_month` on any product, then on any tier marked live. | Unchanged in shape. The site's field must say which allowance it is: per signing key with no purchase (JS 9), or a bought key's own monthly allowance (JS 8.1). If the site lists both, the line takes the first and says "for each key". |
| `src/arcaeon/remote/catalog.py:285-298` (`buy_lines`) | Free line, plan lines, pricing line. | Gains nothing else. Plan lines stay as the price list gives them; no line names a contract pin. |
| `src/arcaeon/cli.py:1003-1039` (`_buy`) | Reads the list, prints lines or one link. | Unchanged. JC 1 keeps `buy` as it is. |
| `src/arcaeon/cli.py:59` | `"buy": ("remote", "print the plans on sale from arcaeon.io (opens nothing)")` | Unchanged. |
| `README.md:163-164` | "`arcaeon buy`: prints a checkout link ..." (pull request 9 rewrites these lines) | Adds that a key with no purchase has a free monthly allowance, and that a bought plan adds pins to a key. |
| `docs/VERBS.md:789-799` (`buy`, "Answers") | Describes the list (pull request 9 rewrites this paragraph). | Adds one sentence on the free line: per key, per UTC month, read from the price list, left out when the list does not state it. |
| `QUICKSTART.md`, section 2 (pull request 12) | Says what `buy` prints. | The same added sentence as VERBS. |

## 2. The no-key refusal and what it says a key is

Under JS 8 and 9, a contract pin with no `ARCAEON_KEY` is not refused: it is
sent and draws on the free allowance of the key that signed it. So the
refusal that fires today when `ARCAEON_KEY` is unset stops being true for
contract pins.

| File and line | Now | Under the spec |
|---|---|---|
| `src/arcaeon/remote/offers.py:20-24` (`KEY_SENTENCES`) | "An Arcaeon key (ARCAEON_KEY) is a secret that lets the hosted witness record pins in your name ... A key is made for you free ... a plan you buy ... adds pins to it." | Two keys must be told apart: the signing key arcaeon makes on your machine (JC 4), which says who wrote the pin and gets the free allowance, and `ARCAEON_KEY`, which only pays (JS 8.1). Suggested: "arcaeon signs each pin with a key it makes on your machine, and that key gets free pins each month. ARCAEON_KEY is a separate key that pays for pins past those; a plan you buy (`arcaeon buy` lists them) adds pins to it." |
| `src/arcaeon/remote/offers.py:93-103` (`upgrade_message`) | Opens with "... no ARCAEON_KEY is set, so nothing was sent." | For contract pins this message is not used: no key is not a refusal. It stays for plain pins only, while they exist (JC open question 1). The out of pins lines of JC 7 replace it where the witness answers 402. |
| `src/arcaeon/remote/offers.py:17` (`WITNESS_ENDPOINT`) | `https://witness.arcaeon.io` | Unchanged. JC 2 adds `/witness/v1` for contract pins. |
| `src/arcaeon/mcp/server.py:344-360` (`_witness_call`) | Refuses with `upgrade_message` when no `ARCAEON_KEY` is set. | For contract pins, sends the pin without `Authorization`; refusals become JC 7's lines. |
| `src/arcaeon/mcp/server.py:849` | `"key_present": _key() is not None` | Adds whether the signing key exists, and the built in witness key id (`witness_key_id`), so an agent can see which witness its receipts must come from. |
| `src/arcaeon/mcp/server.py:857-870` (`arcaeon_status` notes) | Includes a note on the registration grant and "Auth is bearer-key only (auth_level bearer-stage0) ... Owner-signature auth is designed, not built." (pull request 8 replaces the first.) | The second becomes false for contract pins: they are signed by the owner's key and the witness checks the signature (JS 5 step 7). Reworded to say so, and that `ARCAEON_KEY` only pays. |
| `src/arcaeon/serve/h_pin.py:41-43` | `if not remote.key(): return _refused(upgrade_message(tool))` | As the MCP gate: a contract pin goes out without a bearer key. |
| `src/arcaeon/remote/sealed_scan.py:139-147` (`sealed_scan_refusal`) | Refuses a seal when no key is set. | A sealed scan is a contract pin of the seal ledger's head; with no `ARCAEON_KEY` it draws on the free allowance instead of refusing. |
| `src/arcaeon/remote/sealed_scan.py:150-153` (`_insufficient_credit`) and `:212-217` | Takes the plain path's `credit_exhausted` or any 402 as out of credit; the message names a pack price (pull request 8 replaces it with the pricing page). | Takes a 402 naming `plan` as out of pins, and prints JC 7's two out of pins lines, chosen by whether a bearer key was sent. |
| `README.md:150`, `:152`, `:157`, `:162`, `:166` | "Needs `ARCAEON_KEY`" for `pin --remote` and `seal`; "`ARCAEON_KEY` is the one setting." | For contract pins `ARCAEON_KEY` is optional and only pays. The README gains the signing key (where it lives, that it is never sent) and loses "the one setting". |
| `docs/VERBS.md:206-216` (`pin`) and `:478-479` (`seal`) | "`--remote` (needs `ARCAEON_KEY`)"; "With no `ARCAEON_KEY` it prints 'sealed scan is a paid Arcaeon tool ...'". | The same change as the README; the `seal` line is replaced by JC 7's table. |
| `src/arcaeon/cli.py:41` and `:48` (verb list) | `pin`: "... (local file, or --remote)"; `seal`: "PAID: ... (needs ARCAEON_KEY)" | `seal`: "(free pins each month; ARCAEON_KEY pays past them)". |
| `src/arcaeon/cli.py:552-566` (`pin` help) | "Hosted: --remote (POST to the hosted witness; needs ARCAEON_KEY)" and `--ns` "defaults to one derived from your key's prefix". | Says the pin is signed with the key arcaeon keeps on this machine, `ARCAEON_KEY` is optional, and `--ns` defaults to a name carrying the signing key's id (JC 4). |
| `src/arcaeon/cli.py:775-795` (`seal` help) | "Needs ARCAEON_KEY and nothing else" and the prefix retry. | As `pin`; the prefix retry text goes (next table). |

## 3. The namespace prefix learned from `ARCAEON_KEY`

On a contract pin the bearer key's namespace prefix is not checked (JS 8.1):
the pin's signature decides who may write a namespace, and the first key to
pin a name owns it (JS 7.7). So the whole "learn the prefix from a 403 and
retry" path is not needed there, and the default namespace is built from the
signing key instead (JC 4).

| File and line | Now | Under the spec |
|---|---|---|
| `src/arcaeon/cli.py:609-613` | Picks `_pin_ns_from_key` when `--ns` is not given. | For contract pins, the default name is `<ledger name part>-<first 16 hex of the signing key id>`. |
| `src/arcaeon/cli.py:618-620` (`_PIN_NS_BASE`) | `"arcaeon"`, the first try before the prefix is known. | Not used for contract pins. |
| `src/arcaeon/cli.py:623-640` (`_ledger_ns_part`) | `ledger-<12 hex>` from the ledger's first row. | Kept as the name part. |
| `src/arcaeon/cli.py:643-666` (`_pin_ns_from_key`) | Tries a namespace, reads a 403 naming the key's prefix, retries once. | Not used for contract pins. A 422 naming `key_id` (the name belongs to another key) is never retried (JC 4, 7). |
| `src/arcaeon/remote/sealed_scan.py:88-97` (`_prefix_cache`, `_key_id`, `_reset_prefix_cache`) | A per process cache from a hash of `ARCAEON_KEY` to its learned prefix. | Not used for contract pins. `_key_id` here is a hash of the bearer key and must never be confused with the contract `key_id` (the hash of the signing key's public half); renaming it `_bearer_hash` avoids that. |
| `src/arcaeon/remote/sealed_scan.py:100-118` (`prefix_from_refusal`, `namespace_for_prefix`) | Read the prefix from a 403 and build `<prefix>-sealed-scans`. | Not used for contract pins; the sealed scan namespace becomes `mcp-vet-sealed-scans-<first 16 hex of the signing key id>`. |
| `docs/VERBS.md:213-216` (`pin`, `--ns`) and `README.md:157-161` (`seal`) | Explain the key prefix and the retry. | Explain the signing key's id in the name, and that a taken name is refused, not retried. |

## 4. The witness a key is sent to

| File and line | Now | Under the spec |
|---|---|---|
| `src/arcaeon/remote/witness.py:25`, `:30-33` (`base_url`) | `ARCAEON_WITNESS_URL` or the built in address; the key is sent to whatever answers there. | Unchanged for plain pins. For contract pins, JC 2 and 5: a built in `CONTRACT_WITNESS_KEY_ID` (and next id), `ARCAEON_WITNESS_KEY_ID` to override it, `GET /witness/v1/key` checked against it before anything is sent, and `ARCAEON_WITNESS_URL` without `ARCAEON_WITNESS_KEY_ID` refused. |
| `src/arcaeon/remote/witness.py:79-99` (`BLANK_KEY_ERROR`, `_write`) | A blank key is refused before sending. | Kept for plain pins. A contract pin with a blank `ARCAEON_KEY` is sent with no `Authorization` header, never with an empty one. |
| `src/arcaeon/remote/witness.py:111-120` (`pin`, `renew`) | `POST /api/pin`, `POST /api/renew`. | Unchanged. Contract pins get a new function beside them; JS has no renew, and a pin of the same head is answered 200 with the receipt already held (JS 6). |
| `src/arcaeon/remote/__init__.py:45-51` (`KEY_ENV`, `key()`) | `ARCAEON_KEY`, blank read as unset. | Unchanged. |
| `src/arcaeon/remote/__init__.py:9-10` (module notes) | "One setting: ARCAEON_KEY (the witness key, a bearer credential ...)". | Two keys: the signing key on this machine, and `ARCAEON_KEY`, which pays. |

## 5. What arcaeon writes on your machine

| File and line | Now | Under the spec |
|---|---|---|
| `README.md:186-207` | Names `offers-cache.json` and `activity.jsonl`. | Adds `witness/owner.key` (the signing key: the person only may read it; never sent, printed or logged) and `receipts/<witness key id>/<namespace>.<witness_seq>.json` (each receipt as received; never replaced) (JC 4, 6). |

## 6. Not changed

`arcaeon credits` (`src/arcaeon/cli.py:971` onward) reads the plain path's
balance and is not part of the join. `arcaeon stamp` (`src/arcaeon/cli.py:941`)
and its free daily allowance are not part of the join either.
