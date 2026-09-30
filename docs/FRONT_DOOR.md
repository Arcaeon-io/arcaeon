# The front door

The place an agent lands on the MCP server: one tool, `arcaeon_front_door`,
and the server's instructions pointing at it. `arcaeon mcp --print-front-door`
prints the same object as JSON for a person without an MCP client.

## Findings (read before building, 2026-09-29)

What an agent met on this branch before the change, read from the source:

- `src/arcaeon/mcp/server.py` listed nineteen tools: ledger (five), vet
  (three), witness (two, the only paid ones), deal (three), `mandate_check`,
  second reader (`second_read_submit`, `second_read_compare`), evidence pack
  (`evidence_pack_build`, `evidence_pack_verify`) and `arcaeon_status`. The
  second reader and evidence pack tools are already on `main` (0.10.0), so the
  front door names them as present, not coming.
- The instructions were one paragraph naming ledger, vet and witness only; the
  deal, mandate, second reader and evidence pack tools were not mentioned. It
  used an em dash and hyphenated words. It ended with the registration
  sentence only when registration is on (`_registration_suffix`).
- `arcaeon_status` notes carry the grant sentence (`registration_sentence()`),
  the bearer key warning, the tamper evidence is not truth line and the call
  record line. `upgrade_message()` is the keyless refusal from the witness
  tools.
- `src/arcaeon/remote/registration.py`: `registration_link(offers)` returns the
  URL only when the offers document has a top level
  `"registration": {"enabled": true, "url": "https://..."}`; anything else is
  None. `registration_line()` is the one sentence, None when dark. The bundled
  snapshot has no `registration` object, so today it is dark.
- `src/arcaeon/remote/offers.py` and the bundled `offers.json` (updated
  2026-09-27): the `arcaeon` package is free (`price_usd: 0`), and building and
  verifying on your own machine needs no account. The hosted witness mini pack
  is $5 for 1,000 pins at $0.005 per pin. The `registration_grant` statement is
  "500 credits, one time, per verified email", status "in the next release, no
  date promised". The offers note says there is no free window by calendar.
  `PRICING_URL` is https://arcaeon.io/pricing and `CATALOG_URL` is
  https://arcaeon.io/.well-known/offers.json. The hosted witness description
  field and the grant note both contain the word registration, so the front
  door reads only the statement and status, not those fields.
- The can and cannot list: the site page `can-and-cannot.html` (in the site
  repository, outside this one) has a `#cannot` section with three h3 headings
  and fifteen items and a `#can` section with four items. No file in this
  package is the site's source for that list; `docs/WHAT_IT_CAN_AND_CANNOT_PROVE.md`
  is the long version, worded from the README, and differs from the page. So
  the package carries the page's list as a constant, and a test holds the two
  together.
- README "The AI door" said `arcaeon mcp` gives "the ledger, vet and witness
  tools" and named `--tools`; nothing told an agent where to start.

## What the front door returns

`arcaeon.mcp.front_door.front_door()`:

- `no_key`: the local core, grouped as `record`, `verify`, `evidence_pack`,
  `second_reader` and `about`, each with a one line `what` and its tools. The
  groups are exactly the server's free tools (a test holds this). Every check
  runs on this machine; `evidence_pack_verify` with `remote` true is the one
  call that reads the public witness.
- `with_a_key`: `ARCAEON_KEY`, the two witness tools, what a pin does, the per
  pin price and the smallest pack read from offers.json, and the grant sentence
  and its status read from offers.json. No date.
- `get_a_key`: the registration link when `registration_link()` is not None,
  else the pricing page. Dark, the object has no substring "regist".
- `can_and_cannot`: the site page's list, heading and items.
- `offers_url`: the offers document.

The offers document read is the one handed in, else `$ARCAEON_OFFERS_FILE`,
else the bundled snapshot. Nothing opens a connection.

## Tests

`tests/test_front_door.py`: dark (no link, no "regist"), a disabled switch,
prices and grant read from offers.json with no date, a fixture offers.json that
switches registration on (link present), the no key groups against
`FREE_TOOLS`, the instructions (three paragraphs, no dashes, no marketing
words), the MCP tool over the SDK client, and the CLI print in process and as a
subprocess. The can and cannot parity test reads the site page named by
`ARCAEON_SITE_CAN_AND_CANNOT` (else `can-and-cannot.html` under
`ARCAEON_SITE_ROOT`) and names the first entry that differs; with neither set,
it skips.
