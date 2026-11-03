# Buyer review of PRs 7 to 10

An outside reader's pass over the four pull requests that make up 0.10.1:
#7 (`arcaeon buy` reads the live price list), #8 (no prices outside `buy`),
#9 (what `buy` sends over the network) and #10 (version 0.10.1). The question
was: what would surprise, confuse or mislead someone who installs the package
and wants to pay for, or learn about, the hosted service?

How it was read: the four PRs merged together locally (no conflicts), built
into a wheel, installed in a clean venv, and run with a fresh home; plus the
live price list and the pricing page as they stood on 2026-11-02, and the
diff itself. Line numbers are in that merged state, at these PR heads:
#7 `9731b20`, #8 `cea474c`, #9 `2824303`, #10 `b3cdace`. "Ran" means the
finding was confirmed by running the wheel; "read" means by reading only.

This file names no price and no payment link on purpose.

Status: two findings (3 and part of 9) are already fixed on #7 in `cb19aa1`.
The rest are open and listed with a suggested fix for the owner to decide.

## 1. The monthly plan is missing from `buy`, and asking for it says it is not on sale (ran)

- Where: `src/arcaeon/remote/catalog.py:185`, which skips any tier whose
  `status` is not `"live"`.
- What happens: the price list's monthly plan (`witnessed`) has a checkout
  link but no `status` field, so `buy` drops it. `arcaeon buy witnessed`
  prints the pricing line, then "no plan named 'witnessed' is on sale", and
  exits 2. The same price list's `payment.note` calls it one of two live
  paid offers, and the pricing page shows it as live.
- What a buyer expects: the subscription is still for sale. What they
  conclude: it was withdrawn. In 0.10.0, `arcaeon buy witnessed` was the
  worked example in docs/VERBS.md; #7 replaced that example, and neither
  CHANGELOG.md:17 nor MIGRATION.md:9 says the plan no longer appears.
- Suggested fix: add `"status": "live"` to that tier on the site (the CLI
  rule stays strict), or decide it is retired and say so in the changelog.

## 2. "Free: 100 pins a month" comes from a passing remark and disagrees with the pricing page (ran)

- Where: `catalog.py:225` reads the number out of the hosted witness
  description's prose; `catalog.py:240` prints it.
- What happens: the number comes from a parenthetical, "the live service
  currently gives 100 free pins a month", in a description whose grant note
  says the monthly free pins will be retired for new keys. The pricing page
  does not mention a monthly free allowance at all.
- What a buyer expects: a free tier they can join today. Nothing in the
  CLI, README or docs says how to get a key for it; as written, the only
  visible way to a key is to pay.
- Also: when the site rewrites that sentence the line quietly disappears;
  and the free allowance the README does document (`stamp` with no key, per
  day) is not what "Free:" shows.
- Suggested fix: have the site add a structured `free_pins_per_month` field
  (the CLI already prefers it) and drop the prose fallback, so "Free:" only
  appears when the site states it on purpose.

## 3. "3 seconds at most" was not true (ran) - FIXED on #7

- Where: `catalog.py:34,54`; promised in the `buy` help, docs/VERBS.md:794
  and CHANGELOG.md:17.
- What happened: urllib's timeout applies to each socket step, not the whole
  request. Through a proxy that answered one byte every 1.5 s, `arcaeon buy`
  took 92 s before printing the fallback line.
- Fixed in `cb19aa1`: the request runs on a daemon thread and is abandoned
  at 3 s overall. Same slow proxy: 3.1 s. Test:
  `tests/test_buy.py::test_the_whole_request_stops_at_the_deadline`.
- Still true, by reading: urllib follows `HTTPS_PROXY` and the Windows
  registry proxy, but not PAC or WPAD scripts. Behind such a proxy the fetch
  fails to the pricing line and the buyer never sees plans in the terminal.

## 4. `buy <plan>` that could not reach the list prints a line that is not a link and exits 0 (ran)

- Where: `src/arcaeon/cli.py:1027-1029`.
- What happens: with the network cut, with the opt-out set, or with a
  missing `--offers` file, `arcaeon buy mini` prints "Prices and how to buy:
  ..." and exits 0. A typo of the plan name goes unreported when offline.
- What a buyer or a script expects: a link on stdout, or a failure. A script
  such as `open "$(arcaeon buy mini)"` gets the sentence as its URL. The
  README's one exit-code table (README.md:202) says 3 means COULD NOT LOOK;
  this is a `buy` that could not look and reports success. `--offers FILE`
  with an unreadable file used to exit 2; it now exits 0.
- Suggested fix: keep bare `arcaeon buy` at exit 0 (the pricing line is a
  full answer), but have `arcaeon buy <plan>` exit 3 when the list could not
  be read, and `--offers` with an unreadable file exit 2 as before.

## 5. The plan lines do not say what kind of purchase it is or what happens after paying (ran)

- Where: `catalog.py:242`; the output has no header row.
- What happens: each line is a plan name, a price, a count and a link.
  Nothing says these are one-time prepaid packs, that the count is pins
  included rather than a cap, or that a credit is one pin (the CLI and docs
  speak of credits and a balance elsewhere). Nothing says where the key
  comes from after paying, or whether a pack tops up an existing key or
  makes a new one. The price list's own caveats (the largest pack is
  throttled at about 100 pins an hour; no real purchase has completed yet;
  the manual fallback by email) never reach the buyer.
- Suggested fix: one header line and one closing line, both read from the
  price list (for example a `buy_note` field the site writes), so the words
  stay in one place.

## 6. `ARCAEON_OFFERS_FILE` silently replaces the live list (ran)

- Where: `cli.py:1018-1019`.
- What happens: pointed at the old 0.10.0 bundled file, `arcaeon buy` prints
  the old plans and links with the same footer and no sign they came from a
  local file. The variable is in no help text, not in README or VERBS; only
  MIGRATION.md:9 mentions it.
- What a buyer expects: `buy` shows what is on sale now. A variable left from
  an older setup brings back exactly the stale links #7 set out to remove.
- Suggested fix: drop the environment variable (keep `--offers` for tests),
  or print "read from <file>, not from arcaeon.io" on stderr when it is used.

## 7. The no-key refusal is thin, and reads oddly from the CLI (ran)

- Where: `src/arcaeon/remote/offers.py:93-95`; `sealed_scan.py` passes the
  same text through for `seal`.
- What happens: `arcaeon seal` with no key says "It pins your ledger head ...
  the only thing that catches truncation" (a pin, not a seal) and "set
  ARCAEON_KEY ... in this server's environment", although the user ran a
  command, not a server. It names nothing free on the hosted side and does
  not say how a key is obtained. docs/VERBS.md:479 says the refusal tells you
  "where to get a key"; it gives only the pricing page. The free self-host
  route (`ARCAEON_WITNESS_URL`) is not mentioned.
- Not from these PRs, but next to it: `arcaeon credits` with no key says the
  key "was empty or whitespace" even when it is unset.
- Suggested fix: one sentence per caller (server or command line), and a
  line naming the self-host route, both free of prices.

## 8. `buy evidence-pack` and the grant are gone with no pointer (ran)

- What happens: `arcaeon buy evidence-pack` and `arcaeon buy grant` now give
  the generic "no plan named ... is on sale" and exit 2. The first used to
  say the local pack is free forever and that hosted sealing comes later.
  The only trace is CHANGELOG.md:17, "that pack is not on sale", which reads
  as cancelled rather than not yet.
- Suggested fix: reword the changelog line to "not on sale yet; the local
  pack stays free". The P2 rule (nothing unshipped in package text) argues
  against restoring the old message.

## 9. A price is still in the code, and a comment named a removed constant (read)

- `src/arcaeon/remote/offers.py:20-37`: `SEALED_SCAN_PACK` still holds a
  price and a scan count (not printed anywhere). The comment above it still
  said "contrast MINI_PACK, which has a live URL". The comment is FIXED on
  #7 in `cb19aa1`; the numbers remain.
- `src/arcaeon/record/receipt/ballot.py:64-71`: still hard-codes the entry
  pack's per-pin rate and writes its source into ballot ledger rows (line
  166). Internal cost accounting, not printed by any command; changing it
  changes how the cost ceiling works.
- Both sit against #8's claim of "no prices outside buy". Suggested fix: say
  "no prices printed outside buy" in #8, or move both numbers out.

## 10. Local writes the docs do not mention (ran)

- `buy` writes `offers-cache.json` (the whole price list, about 17 KB, mode
  644) into ARCAEON_HOME or `~/.arcaeon`. README and VERBS say "kept for 10
  minutes" but name no file. It is never deleted once stale, and setting
  `ARCAEON_OFFERS_OFFLINE` does not remove it.
- `buy` appends a line to `activity.jsonl`. For `buy <plan>` the stored
  target is the sha256 of the plan name, which anyone can reverse from the
  short list of plan names. `ARCAEON_JOURNAL=0` turns it off. The "one
  request" wording mentions neither write.
- The opt-out also accepts `true`, `yes` and `on`; the docs only show `1`.
- Suggested fix: one sentence in README and VERBS naming the cache file and
  the journal line; skip journaling the plan name for `buy`.

## 11. Stale or mixed text a buyer would read (read)

- MIGRATION.md:302 still says, in the present tense, that `arcaeon buy`
  reads the bundled `offers.json`, which no longer exists.
- docs/VERBS.md:769: the `credits` example says "7 of 50 free pins used this
  month" (marked as made up); next to `buy`'s "Free: 100 pins a month" it
  reads like a real, different cap.
- CHANGELOG.md:13 and MIGRATION.md:7-12 call 0.10.1 a patch where "nothing
  was renamed", yet it removes public Python names (`OFFERS_SNAPSHOT`,
  `MINI_PACK`) and `load_offers()` now raises; and the evidence pack's
  `pack_schema` 1 to 2 change moved into this patch. The section says "not
  released" while the wheel, `arcaeon version`, registry/server.json and
  openapi.json already say 0.10.1; the live price list still says 0.10.0.
- README.md:164 and docs/VERBS.md:217 still say "no credit spent" and "costs
  no credit"; #8 rewrote the matching sentence at VERBS.md:450 as "spends
  nothing". Harmless, but the words differ.

## Windows (read)

Output is plain ASCII, so console code pages are fine. The cache lives under
`Path.home()/.arcaeon`; a cache write blocked by another process holding the
file is caught and only costs one more request. The real Windows risk was
the timeout in finding 3 (now fixed) and PAC proxies (still open).

## What was not checked

The PowerShell forms in #12; a real purchase; what the checkout and the
key-minting step look like after paying.
