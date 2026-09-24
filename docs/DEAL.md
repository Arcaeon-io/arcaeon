# The deal lane: `arcaeon deal`

A witnessed transaction. The buyer's agent and the seller each keep a
hash-chained record of the same steps, and either side, or anyone they hand the
two records to, can line them up and get one verdict.

## The problem

Card networks settle one question: was this the cardholder's card. An agent
buying on a person's behalf raises three more that nobody records in a form both
sides can check later. Did the person authorize this agent to do this specific
thing? Did the agent and the merchant agree on the same terms? When did each
step happen relative to the others (the cancel-before-ship fight)? Today each
side keeps its own story and the other side can call it made up. The deal lane
gives both sides a hash-chained record of the same steps, which a witness pin
stops either side from quietly rewriting, and a verdict that is the evidence
pack.

## The steps, one line each

Every step is one row on the writer's own ledger (`arcaeon verify` checks it
like any other ledger). The fields both sides must agree on go in the row's
`shared` body, and its digest is the row's `step_digest`.

    arcaeon deal mandate  buyer.jsonl  --deal ID --merchant M --cap 60.00 --currency USD --not-after T   # buyer only
    arcaeon deal commit   <ledger> --deal ID --party buyer|seller --seller M --item SKU:QTY:PRICE --total 19.00 --currency USD
    arcaeon deal pay      <ledger> --deal ID --party buyer|seller --rail card --reference REF --amount 19.00 --currency USD
    arcaeon deal ship     seller.jsonl --deal ID --carrier ups --tracking 1Z...          # the buyer may mirror
    arcaeon deal deliver  <ledger> --deal ID --party buyer|seller --proof EVENT-ID
    arcaeon deal cancel   buyer.jsonl  --deal ID --reason "..."                          # the seller may mirror

Each step prints one JSON line on success, the row it wrote under its deal id
(`--deal` may be left off `mandate`, which then mints an id and prints it here):

    {"deal": "d-demo1", "row": {"kind": "deal.mandate", "deal": "d-demo1", "party": "buyer", "step_digest": "sha256:json-c14n:v1:...", "mandate_digest": "sha256:json-c14n:v1:c316bef...", ..., "chain": "..."}}

The `mandate_digest` on the mandate line is the one the seller's commit cites.

Then `arcaeon deal dispute ID --buyer B --seller S` gives the verdict and
`arcaeon deal pack ID --buyer B --seller S -o DIR` writes it out for a person.
`arcaeon deal show LEDGER --deal ID` prints one ledger's rows for a deal; a
ledger that is missing, a directory, not UTF-8 text, or holds no row of the
deal prints one COULD NOT LOOK line instead and exits 3.

What is compared: `commit` and `pay` must be on both tapes. `ship`, `deliver`
and `cancel` are written by one side and may be mirrored by the other; when only
one side has one, that is not a finding, and the verdict's `position` says which
tape lacks it. A `mandate` is the buyer's alone: the seller never holds it, but
the seller's commit must cite the buyer's mandate digest. A `dispute` row is one
side's claim and is never compared. The buyer's commit records
`inside_mandate` (seller, currency, cap and window checked against the mandate);
a commit outside the mandate is still written, with `inside_mandate: false` and
the reason, because the record never refuses to record.

## A worked example

Every command below is run by the test suite (`tests/test_deal.py`), in this
order, in an empty directory, and the first line printed by each `dispute` must
be the line shown under it. Each step's JSON line is shown cut
short (`...`); the test checks the part before the cut.

The buyer's agent writes its mandate, then commits. The seller commits to the
same terms, citing the mandate digest it got in the buyer's commit message.

```console
$ arcaeon deal mandate buyer.jsonl --deal d-demo1 --merchant acme-store --cap 60.00 --currency USD --not-before 2026-01-01T00:00:00Z --not-after 2099-12-31T00:00:00Z --may "office supplies"
{"deal": "d-demo1", "row": {"kind": "deal.mandate", ...}}
$ arcaeon deal commit buyer.jsonl --deal d-demo1 --party buyer --seller acme-store --item pens-12:2:9.50 --total 19.00 --currency USD --ship-to "1 Main St" --buyer-ref po-77
{"deal": "d-demo1", "row": {"kind": "deal.commit", ...}}
$ arcaeon deal commit seller.jsonl --deal d-demo1 --party seller --seller acme-store --item pens-12:2:9.50 --total 19.00 --currency USD --ship-to "1 Main St" --buyer-ref po-77 --mandate-digest sha256:json-c14n:v1:c316befba19c9cf5a96496674ed8fe1410fc0f92d5a8f9ccefea3052cc3f41d6
{"deal": "d-demo1", "row": {"kind": "deal.commit", ...}}
```

Both record the payment reference the card rail issued, the seller ships, and
the buyer records the delivery.

```console
$ arcaeon deal pay buyer.jsonl --deal d-demo1 --party buyer --rail card --reference ch_3Pq --amount 19.00 --currency USD
{"deal": "d-demo1", "row": {"kind": "deal.pay", ...}}
$ arcaeon deal pay seller.jsonl --deal d-demo1 --party seller --rail card --reference ch_3Pq --amount 19.00 --currency USD
{"deal": "d-demo1", "row": {"kind": "deal.pay", ...}}
$ arcaeon deal ship seller.jsonl --deal d-demo1 --carrier ups --tracking 1Z999AA10123456784 --at 2026-09-24T15:00:00Z
{"deal": "d-demo1", "row": {"kind": "deal.ship", ...}}
$ arcaeon deal deliver buyer.jsonl --deal d-demo1 --party buyer --proof ups-event-88121 --at 2026-09-26T11:00:00Z
{"deal": "d-demo1", "row": {"kind": "deal.deliver", ...}}
```

Either side asks for the verdict:

```console
$ arcaeon deal dispute d-demo1 --buyer buyer.jsonl --seller seller.jsonl
MATCHED 2 of 2 compared steps
```

The lines under it (`position`) say what the rows show, step by step, with no
verdict word: the seller's ship row has no buyer mirror, the buyer's deliver row
has no seller mirror, and the buyer's commit recorded `inside_mandate true`.

Now a second deal on the same two ledgers, where the seller's record of the
terms carries a different price:

```console
$ arcaeon deal mandate buyer.jsonl --deal d-demo2 --merchant acme-store --cap 60.00 --currency USD --not-before 2026-01-01T00:00:00Z --not-after 2099-12-31T00:00:00Z --may "office supplies"
{"deal": "d-demo2", "row": {"kind": "deal.mandate", ...}}
$ arcaeon deal commit buyer.jsonl --deal d-demo2 --party buyer --seller acme-store --item pens-12:2:9.50 --total 19.00 --currency USD --ship-to "1 Main St" --buyer-ref po-78
{"deal": "d-demo2", "row": {"kind": "deal.commit", ...}}
$ arcaeon deal commit seller.jsonl --deal d-demo2 --party seller --seller acme-store --item pens-12:2:11.50 --total 23.00 --currency USD --ship-to "1 Main St" --buyer-ref po-78 --mandate-digest sha256:json-c14n:v1:c316befba19c9cf5a96496674ed8fe1410fc0f92d5a8f9ccefea3052cc3f41d6
{"deal": "d-demo2", "row": {"kind": "deal.commit", ...}}
$ arcaeon deal dispute d-demo2 --buyer buyer.jsonl --seller seller.jsonl
ALTERED at commit#1: commit #1 differs between the tapes in terms.items, terms.total (buyer row 6, seller row 4)
```

Exit code 1. The other deal on the same ledgers is untouched by this: a dispute
reads only the rows of the deal it names. To hand it to a person:

```console
$ arcaeon deal pack d-demo2 --buyer buyer.jsonl --seller seller.jsonl -o DEAL-d-demo2
ALTERED at commit#1: commit #1 differs between the tapes in terms.items, terms.total (buyer row 6, seller row 4)
```

`DEAL-d-demo2/` holds `verdict.json` (the whole report), `timeline.md` (one
page: the verdict word on its first line, the timeline, what the rows show, the
digests, the pins, and how to check it yourself) and each side's rows for this
deal (`buyer.deal.jsonl`, `seller.deal.jsonl`).

## Pins: bounding when a row existed

Without a pin, both tapes rewritten in agreement still match each other. Pin
each ledger with a witness on your own cadence, and pass the pin file:

    arcaeon pin buyer.jsonl --ns acme-buyer --witness witness.jsonl
    arcaeon deal dispute d-demo1 --buyer buyer.jsonl --seller seller.jsonl --pins witness.jsonl --buyer-ns acme-buyer

The pin check is reconcile's own: fewer rows than pinned is MISSING, a
different chain at the pinned row is ALTERED. A pin file may be one pin, a list
of pins, a `{"buyer": pin, "seller": pin}` pair, or a witness JSONL file. A pin
naming `side` goes to that tape; otherwise `--buyer-ns` / `--seller-ns` match it
by namespace; with neither, a pin is held against both tapes. A timeline row
covered by an agreeing pin shows the pin's time as "existed by".

## The verdict

`MATCHED` (exit 0), `MISSING` or `ALTERED` (exit 1), `COULD NOT LOOK` (exit 3),
bad usage 2: the words and codes every `arcaeon` check uses. A tape that does
not verify, cannot be read, or holds no row of the deal is COULD NOT LOOK, and
the reason names the side. A finding beats a could-not-look; only a comparison
of at least one shared step with nothing found and nothing unlooked-at is
MATCHED. `--json` prints the whole report. `--remote` is reserved for the
hosted verdict, which does not take deal tapes yet; it prints that and keeps
the local verdict and exit code. `--legacy-exit` changes nothing: this verb is
new.

## What it does not prove

- MATCHED means the buyer's and the seller's tapes agree; a buyer side and a
  seller side run by one party who wants a lie can write two agreeing tapes.
- A step neither side recorded leaves no row on either tape; the deal lane
  records what each side wrote, not what happened in the world.
- Digests compare content (canonical JSON), not bytes: a meaning-preserving
  re-serialization in transit is MATCHED by design.
- Without a witness pin, both tapes truncated or rewritten in agreement still
  match; a pin bounds that to the rows written after it.
- Times are each writer's own ledger ts; only a witness pin bounds when a row
  existed.

## What it is not

- It never moves money, holds money, or talks to a payment rail. `pay` records
  a reference string the rail already issued.
- It does not enforce windows. It records when the cancel row and the
  fulfillment row exist, and pins bound those times. The merchant's policy
  decides the refund; the record decides the facts.
- It adds no verdict words and no runtime dependency.
- It is an evidence pack a person can hand to whoever decides. It is not a
  ruling.
