# Phone screens spec

Design through Claude Design before code. This is a document, not a build: no native phone code, no mockup images, no account login ship in this batch. The look (navy #0C1828 / gold, the C2 chevron mark, type, spacing) comes from the Claude Design system later; nothing below is a visual decision.

## What the phone face is for

A person who runs arcaeon on a laptop wants to glance at a phone and know one thing: did the last checks come back good, bad, or unread. The phone answers in the same sentences the dashboard uses (`arcaeon.words`) and the same verdict words (`arcaeon.verdict`, `docs/WORDS.md`). It never invents a word of its own and never rounds a verdict up.

## The one rule that shapes every screen: a phone cannot see the local ledgers

`arcaeon serve` binds 127.0.0.1. A phone is another machine, so it cannot reach that server, and it cannot read the ledgers, tapes, packs or journal that live on the laptop. Opening the server to a network is a deploy decision, not something the phone app does, and this spec does not assume it.

So the phone has exactly two sources:

1. **Account-side data**, after a sign-in that does not exist yet (later, through Claude Design): what the hosted side itself holds. See the account-only list below.
2. **Nothing local.** Until the owner deliberately pairs the phone with a local server (a later decision, with its own spec), every local tile on the phone reads "Not visible from this phone" in grey. That is a statement about the phone, not about the files.

If a pairing ever exists, every local reading goes through the local server's token and fence, exactly as the browser dashboard does: the phone would send a bearer token to the paired server and get the same JSON the CLI's `--json` prints. The phone never reads a file, never holds a ledger copy, and never computes a verdict itself.

## Screens

### 1. Glance

Tiles in a single column, one reading each, each with its time:

| tile | what it shows | source |
|---|---|---|
| Last checks | the status sentence, for example "You checked 3 files today. One could not be read (missing)." | local, via `GET /v1/status` on a paired server; grey "Not visible from this phone" otherwise |
| Open unread checks | a count of open COULD NOT LOOK items, each with its reason word (`missing`, `unreadable`, `network` ...) | local, `open_could_not_look` from `GET /v1/status`; grey otherwise |
| Witness pins | the last time a ledger head was pinned with the hosted witness, per namespace | account-only |
| Credits | the balance sentence, as the witness states it | account-only |

A tile with no reading yet says so ("No reading yet") in grey. It never shows an empty green box.

### 2. Tile detail

Tapping a tile shows the reading behind it in plain sentences: the verdict word, the sentence from `arcaeon.words`, the time it was read, and where it came from (paired server or account). For a COULD NOT LOOK it names the reason word and says what would let it look (for example "the file was missing when checked").

### 3. Account

Placeholder only in this batch. It will hold sign-in, namespaces and credits once accounts exist. Until then the screen says "Accounts are not built yet" and offers nothing to tap.

### 4. About

What the phone can and cannot see (the rule above, in two sentences), and a link to `docs/WHAT_IT_CAN_AND_CANNOT_PROVE.md` on the site.

## Account-only data (what a signed-in phone may read from the hosted side)

- the namespaces the account's key may pin into;
- the last pinned head and its time per namespace, as the witness recorded it;
- the credit balance and recent seal receipts (the badge ids, not the files sealed);
- the account's own settings.

Account data says what the hosted witness recorded. It does not say anything about files on the laptop, and the phone must not present it as if it did: a recent pin is "a head was pinned at 10:42", not "your records are fine".

## What the phone must never show

- file contents, ledger rows, tape rows, pack files or journal lines;
- full local paths or usernames from the laptop (the fence already keeps these out of server answers; the phone must not rebuild them);
- the serve token, a key, a one-time sign-in code, or any secret, even masked;
- a verdict the phone worked out itself;
- a green state for anything the phone could not read.

## The never-green rule

Green means one thing: a good verdict (a word whose tone in `arcaeon.words` is ok: VERIFIED, MATCHED, COMPARED) that was read recently. Everything else is not green:

- COULD NOT LOOK is never green, and never shown in the good color with a small warning beside it. It is grey with its reason word.
- BROKEN, ALTERED and MISSING are red, with the sentence.
- A tile the phone cannot see is grey, "Not visible from this phone".
- A green that is older than its tile's freshness window turns grey and says how old it is ("Last good check 3 days ago"). A stale green is not a current good. The windows per tile are in `docs/design/HUD_TILES_SPEC.md`.
- A failed fetch (no signal, server gone, account side down) turns every tile it fed grey. It never leaves the last green up.

## Out of scope here

Native code, app store listings, push notifications, sign-in, pairing, and the visual design. Each of those comes after the Claude Design pass, as its own item.
