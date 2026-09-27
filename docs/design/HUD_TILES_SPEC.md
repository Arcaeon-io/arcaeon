# HUD tiles spec: one set of tiles, three faces

Design through Claude Design before code. This is a document, not a build: no native app code, no mockup images, no account login ship in this batch. The look of every tile (navy #0C1828 / gold, the C2 chevron mark, type, spacing) comes from the Claude Design system later. Until then the browser face uses `src/arcaeon/serve/static/placeholder.css`, which says so in its `TODO(design-system)` header.

## The three faces

| face | where it runs | how it reads | state in this batch |
|---|---|---|---|
| Browser dashboard | a browser on the same machine, pages from `arcaeon serve` | a session cookie from `arcaeon open`'s one-time code; pages rendered server-side | built (K100 to K109) |
| Tray | an icon on the same machine | a click runs `arcaeon open`; any tile it shows later reads the same local routes with the serve token | stub only (`tools/tray/`, K110), not packaged |
| Phone | another machine | account-side data only; local tiles grey unless a later pairing exists | spec only (`docs/design/PHONE_SCREENS_SPEC.md`, K111) |

Every face reads through the local server's token and fence, or through the account, and nothing else. No face opens a file itself, holds a copy of a ledger, or works out a verdict on its own. A tile shows what a route answered, in the words from `arcaeon.words`, with the time it was read.

## The tiles

Each tile names its route, the reading it shows (the JSON field the route answers), and its time (the field the tile's clock comes from). The freshness window is how long a good reading may stay green before it turns grey.

| tile | route | reading | its time | freshness window | faces |
|---|---|---|---|---|---|
| Server up | `GET /health` | `ok` | the moment the face asked | 1 minute | browser, tray |
| Last checks | `GET /v1/status` | `last_run.<verb>.word` and `.exit`, as the status sentence | `last_run.<verb>.t` | 24 hours | browser, tray, phone (paired only) |
| Open unread checks | `GET /v1/status` | `open_could_not_look` (count, then each `verb` and target) | each item's `t` | none: an open COULD NOT LOOK stays grey until a later run clears it | browser, tray, phone (paired only) |
| Credits | `GET /v1/status` | `balance` (the sentence) | the moment the face asked | 1 hour | browser, phone (account) |
| Ledger chain | `POST /v1/verify` | `word` (VERIFIED / BROKEN / COULD NOT LOOK), `rows`, `first_break` | the moment the check ran | 24 hours | browser |
| Tapes | `POST /v1/reconcile` | `word` (MATCHED / MISSING / ALTERED / COULD NOT LOOK) | the moment the check ran | 24 hours | browser |
| Evidence pack | `POST /v1/evidence-pack/verify` | `word` and the three counts (VERIFIED, BROKEN, COULD NOT LOOK) side by side | the moment the check ran | 7 days | browser |
| Second read | `POST /v1/second-read/compare` | `disagreed` and `read`, two integers, never one rate; "not yet informative" under twenty read | the moment the compare ran | 7 days | browser |
| Mandate | `POST /v1/mandate/check` | `verdict` (inside / outside) and `rule` | the moment the check ran | 24 hours | browser |
| Witness pins | account side (not a local route) | the last pinned head per namespace | the time the witness recorded | 7 days | phone (account), browser later |

A tile that has never been read says "No reading yet" in grey. A tile whose route is not reachable from a face (the phone and every local route, until pairing) says "Not visible from this phone" in grey. It is never hidden, so an absence is visible.

## The color of a tile

The tile's state comes from `arcaeon.words.tone` and nowhere else: `ok`, `bad` or `unknown`, the same three classes the browser pages use (`state-ok`, `state-bad`, `state-unknown`).

- **Green (ok):** a word whose own exit code is 0 (VERIFIED, MATCHED, COMPARED), inside its freshness window. For a word `arcaeon.words` does not know (a status row's `OK`), the row's own `exit` decides.
- **Red (bad):** BROKEN, MISSING, ALTERED, and any row whose exit is 1.
- **Grey (unknown):** COULD NOT LOOK, NO GRADEABLE FILES, bad usage, no reading, not visible, a failed fetch, and a stale green.

COULD NOT LOOK is never green. It is never shown in the good color with a small warning beside it, and it never counts toward a "good" total.

## A stale green turns grey

A green reading older than its tile's freshness window turns grey and says how old it is: "Last good check 3 days ago". A stale green is not a current good, and a face must not leave it up as if it were. Red does not fade: a BROKEN stays red, with its time, until a later reading replaces it, because an old bad result is still a result someone has to look at.

When a face cannot fetch at all (the server stopped, no signal, the account side down), every tile that fetch fed turns grey at once, with the time of its last reading. The last green is never left showing over a failed fetch.

## What no tile ever shows

- file contents, ledger rows, tape rows, pack files, journal lines;
- full local paths or usernames (the fence keeps them out of route answers; a face must not rebuild them);
- the serve token, a key, a one-time code after its use, or any secret, even masked;
- a verdict the face worked out itself, or a word that is not in `arcaeon.verdict` or `arcaeon.words`;
- a paid action on a tap. `POST /v1/seal` is not a tile and no face offers it as a button in this batch.

## Out of scope here

Native tray and phone code, packaging `arcaeon[desktop]`, sign-in, pairing a phone with a local server, and every visual decision. Each comes after the Claude Design pass, as its own item.
