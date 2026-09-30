# The second reader

## Findings: a language model is not a witness

Research for `evidence-pack verify --second-reader`, 2026-09-29, read only.
Sources: the two internal notes on the second reader demo (run 1, and run 2
where the model held a sha256 tool; the harness has a `--run3` mode, but no
run 3 note existed when this was written), the demo harness, the pack builder
(`arcaeon.prove.evidence_pack`), the pack verifier
(`arcaeon.prove.evidence_pack_verify`) and the MCP server
(`arcaeon.mcp.server`).

**What the runs showed.** The demo handed one model, at temperature 0, the
four row fixture pack and a copy of it with one byte changed in records.jsonl
row 2 (`lookup` to `lookuq`) and one in README.md (`folder` to `fo1der`), the
manifest untouched. In run 1 (no tool), 19 of its 21 VERIFIED lines held, but
only 11 were recomputations: it wrote "Hashed the provided bytes" on hash
lines and, on another call, said it cannot compute SHA-256. On the tampered
copy it called the chain head VERIFIED by reading the stored `chain` field of
the last row, which the tamper left alone. In run 2 (a real sha256 tool)
every digest it printed was real and 18 of 21 VERIFIED lines were
recomputations, yet 3 were false on the tampered copy: two where it printed
the mismatching digest and wrote "does not match manifest" under a VERIFIED
verdict, and the chain head read off the stored field again. So a model
either agrees with the pack or calls a mismatch VERIFIED. The digest column
proved which bytes it read, not that the line was recomputed.

**What that asks of a program.** VERIFIED must mean recomputed and equal,
never "I looked at it". A recomputed value that differs needs its own word,
MISMATCH, and must break the pack. The chain head must be recomputed link by
link from each row's content, never read off the stored field. And the
recomputed value must be printed beside the claimed one, so a reader checks
the row and not the word.

**The table shape.** The demo asked for `# | Claim | Where the pack makes it
| Verdict | How`, the shape the colony liked. The second reader keeps it and
adds three columns: Claimed, Recomputed and Algorithm.

**What a pack claims.** From the builder and the verifier:

- `manifest.sha256` beside the manifest: the sha256 of manifest.json.
- `manifest.json` `files`: the sha256 of every other file in the pack, and by
  implication that the pack holds no other file.
- `chain_head`: the last chain value of records.jsonl and its row count.
- `window`: its agent and bounds, its row count and the ledger lines it holds;
  window.jsonl holds each of those lines byte for byte.
- `pins`: for each witness pin, the namespace, row and chain the witness
  holds. A local pin is checked against the pin file itself, never the pack's
  copy; a remote pin only over the network.
- `audit_export`: record count, unreadable lines, the period covered (first
  and last `ts`) and the event counts.
- `integrity.json`: the records' sha256 and row count, and the witness block.
- `counts`, `checks` and could_not_look.json: what the build could not look at.
- `built_at`, `independence` and `operator_at_t`, and README.md and
  ARTICLE_12_SUMMARY.md, which verify re-renders from the records.
- On the bearer branch (pack schema 2, not yet in main): README.json, the twin
  of page one, lists each sentence's id, line, the sha256 of its text without
  its bracket, and its bearer class (`[bytes]`, `[order]` or `[asserted]`).

**How verify prints today.** One line, `VERDICT: evidence pack PATH`, with
the finding in brackets when BROKEN, then one indented line per COULD NOT
LOOK reason; `--json` prints every check. Exit 0 VERIFIED, 1 BROKEN, 2 bad
usage, 3 COULD NOT LOOK. It names what broke, but it never shows the value it
recomputed beside the value the pack claimed.

**How an MCP tool is added.** A plain handler `_name(args)` imports the
library lazily and does the work; bad usage raises a tool error, every
verdict is an answer with its `exit`. The registered function, under
`@_tool(name=..., description=...)`, names its arguments once, runs the
handler under `_attempt` and ends in `_record_call`, which writes one chained
row to the call record. The tool's name goes in a constant (here
`EVIDENCE_TOOLS`) that the connector tests count.

## Two readers, one sentence

Two readers read one frozen sentence against the same claims. Did they come
out the same way, and how often did they not? That is the whole question
`arcaeon second-read` answers. It files every disagreement with both readings
and both reader ids; it never averages one away.

## What it shows

- **The sentence was frozen first.** `second-read criterion` (or the first
  `submit` or `ask` that names a criterion file) writes the sentence and its
  sha256 into the readings ledger. Every reading cites that sha256, and a
  reading that cites a sentence the ledger never froze is COULD NOT LOOK
  (`name_not_found`). A revised sentence is a new dated row; the old one stays.
- **Each claim, lined up.** `compare A B` files every claim as AGREED,
  DISAGREED, MISSING (read on one side only, `side` names the short ledger) or
  COULD NOT LOOK. A DISAGREED claim carries both readings, both reader ids and
  each side's near-match id. An `undetermined` reading is a reading, carried
  like the others.
- **How often, as two integers.** The count is `disagreed` and `read`, never a
  lone ratio. Under 20 claims read it is still printed, marked not yet
  informative. When it was not computed at all (a ledger broken, missing or
  empty) both are null and `counts_reason` says why.
- **Who read, as the rows assert it.** One reader id on both sides is not a
  second read: COULD NOT LOOK, `bounded`. Two ids from one provider are
  `same_provider`. Two providers are `distinct_provider_self_asserted`.
- **A local receipt of the comparison.** `--receipt OUT` issues the counts,
  the per-claim lines and both ledgers' heads as a receipt; `arcaeon receipt
  verify OUT` catches any later edit by the body digest.

## What it does not show

- **Whether a claim holds.** COMPARED means both ledgers were read and lined
  up. AGREED means two readers read one sentence the same way for that claim.
  Neither says the claim is right, and a DISAGREED claim does not say which
  reader was wrong. The count measures how ambiguous the sentence was for
  these readers.
- **That the readers share no habits.** Two models from one family, or from
  one vendor, were trained on overlapping text and agree more for that reason
  alone. Their agreement is worth less, and the provider field is only what
  each row says about itself.
- **Who wrote a ledger.** Reader ids and providers are self-asserted. Nothing
  here confirms who or what filed a row.
- **Anything to a stranger about when.** The receipt is local and unwitnessed:
  no witness pin, no timestamp anchor. The witness-sealed version is the hosted
  reconcile, which is not deployed.

This design can lose. NP-12's loss condition, quoted: "two readers agree on
more than nine of ten rows under a sentence a third stranger then reads the
other way. If that happens, the two-of-two bar was measuring the readers'
shared habits, not the sentence, and NP-12 is wrong."

## Sending a claim is a disclosure

`ask` (one reader) and `run` (two readers, then one compare) put claims to a
model. Without `--send` they send nothing: they print the endpoint host, the
claim count and the first claim exactly as it would be sent, and exit 0. With
`--send`, each call has a 30 s timeout and one retry at most; a call that
still fails writes no reading for that claim (never a guessed one) and lists
the claim under `could_not_look`. A key is read from the environment variable
named by `--key-env`, never from the command line, and never written down.
Readers follow no redirect and use no proxy.

## Example: two readers file their own readings

`submit` is the door for any AI or person: the reader filed its reading
itself, and no model was called. The lines in `<angle brackets>` vary from run
to run. These examples are run by the test suite, in an empty folder.

```console
$ python -c "open('criterion.txt', 'w').write('Does the claim state the dispatch time?')"
$ python -c "open('c1.txt', 'w').write('Unit 12 was dispatched at 14:02.')"
$ python -c "open('c2.txt', 'w').write('Unit 12 was dispatched after the second call.')"
$ arcaeon second-read submit --ledger a.jsonl --reader-id model-one --provider vendor-one --claim-id c1 --claim-file c1.txt --criterion-file criterion.txt --reading yes
<reading filed: claim c1 read 'yes' by model-one (chain varies)>
$ arcaeon second-read submit --ledger a.jsonl --reader-id model-one --provider vendor-one --claim-id c2 --claim-file c2.txt --reading no
<reading filed: claim c2 read 'no' by model-one (chain varies)>
$ arcaeon second-read submit --ledger b.jsonl --reader-id model-two --provider vendor-two --claim-id c1 --claim-file c1.txt --criterion-file criterion.txt --reading yes
<reading filed: claim c1 read 'yes' by model-two (chain varies)>
$ arcaeon second-read submit --ledger b.jsonl --reader-id model-two --provider vendor-two --claim-id c2 --claim-file c2.txt --reading yes --near-match-id c1
<reading filed: claim c2 read 'yes' by model-two (chain varies)>
$ arcaeon second-read compare a.jsonl b.jsonl --receipt compare.receipt.json
compared 2 claims: 1 disagreed of 2 read
COMPARED: both ledgers were read and lined up
not yet informative: fewer than 20 claims read (2)
readers: distinct_provider_self_asserted
DISAGREED c2: a=no (model-one, near None) b=yes (model-two, near c1)
agreement says nothing about whether a claim holds
receipt written: compare.receipt.json
(exit 0)
$ arcaeon receipt verify compare.receipt.json
"ok": true,
"body_digest_ok": true,
(exit 0)
```

## Example: two models, dry run first

```console
$ python -c "import json; open('claims.jsonl', 'w').write(json.dumps({'claim_id': 'c1', 'claim': 'Unit 12 was dispatched at 14:02.'}) + chr(10))"
$ arcaeon second-read run --claims claims.jsonl --reader-a ollama:qwen2.5-coder:3b --ledger-a run-a.jsonl --reader-b openai_compat:other-model --base-url-b http://127.0.0.1:8000/v1 --ledger-b run-b.jsonl --criterion-file criterion.txt
dry run: nothing sent. would send 1 claims to 127.0.0.1 (ollama:qwen2.5-coder:3b@127.0.0.1) and to 127.0.0.1 (openai_compat:other-model@127.0.0.1); add --send to send
first claim as it would be sent:
Unit 12 was dispatched at 14:02.
(exit 0)
```

Add `--send` to put the claims to both readers; the output then starts with
the same `compared N claims: D disagreed of R read` line as `compare`, and
`--receipt OUT` works there too. Exit codes for `compare` and `run`: 0
COMPARED, 1 MISSING or BROKEN, 2 bad usage, 3 COULD NOT LOOK (a `run` whose
claims all lined up but where some claim got no reading on either side exits
3). Over HTTP the same doors are `POST /v1/readings` and
`POST /v1/second-read/compare`; over MCP, `second_read_submit` and
`second_read_compare`.

## The recomputing reader: `evidence-pack verify --second-reader`

The findings above, built. Where `second-read` lines up two readers of one
sentence, `evidence-pack verify --second-reader` is a reader that is a
program: it recomputes every claim an evidence pack makes from the pack's
bytes, one row per claim, and prints the recomputed value beside the claimed
one.

```text
arcaeon evidence-pack verify PACK --second-reader [--witness PINS]
                             [--json OUT.json] [--markdown OUT.md]
```

PACK is the folder or the .zip `evidence-pack --zip` wrote. `--witness` is
the local pin file the pack's local pins are checked against. The table goes
to stdout; `--json` also writes the machine form to a path, `--markdown` a
table ready to paste. Without `--second-reader`, `verify` prints as before
and its `--json` flag still prints to stdout.

**The rows.** One for manifest.sha256, one per file in the manifest's
`files`, one that the pack holds no unlisted file, the chain head and its row
count, integrity.json's records hash and row count, the window's row count,
its lines and its bytes, the export's record count, unreadable lines, period
and event counts, and for each pin two rows: the records reaching the pinned
chain at the pinned row, and the witness holding the pin. Then one row for
each verify step that re-derives more than one value (the build time
findings, the re-rendered pages and fields, and the AAT, mandate and receipt
sections when the pack has them). A pack with a bearer twin (README.json)
gets two rows per page one sentence: its sha256 and its bracket.

**The words.** Each row carries one of three, and names its algorithm
(`sha256`, the ledger's chain link, a count, a tally, a re-selection, the
witness):

- **VERIFIED**: recomputed, and equal to the claim.
- **MISMATCH**: recomputed, and not equal. The overall verdict is BROKEN.
- **COULD NOT LOOK**: the bytes are not in the pack, or the claim needs the
  witness itself (a local pin with no `--witness`; a remote pin always, since
  the second reader makes no network call).

The chain head is recomputed from each row's content, starting at genesis,
never read off the stored `chain` field of the last row. That is the line
the model got wrong in both runs.

**The overall verdict** is the worst of the rows and of plain `evidence-pack
verify` on the same pack and witness, which the report carries as
`pack_verify`. So it is never less than what verify says: a listed file that
is gone is COULD NOT LOOK on its own row (its bytes are not there) and BROKEN
overall, as verify has it. Exit codes as every verb: 0 VERIFIED, 1 BROKEN, 2
bad usage (an output path that cannot be written), 3 COULD NOT LOOK.

**Example.** The demo's tampered copy, rows 1 to 12 of the Markdown form
with the long hashes cut here for width:

```text
| # | Claim | Where the pack makes it | Claimed | Recomputed | Verdict | Algorithm | How |
|---|---|---|---|---|---|---|---|
| 1 | manifest.json hashes to the value beside it | manifest.sha256 | `fb8c7607...` | `fb8c7607...` | VERIFIED | sha256 | sha256 of manifest.json's bytes |
| 3 | README.md hashes to the listed value | manifest.json files[README.md] | `a890bf52...` | `98cd1856...` | MISMATCH | sha256 | sha256 of the 1770 bytes of README.md |
| 6 | records.jsonl hashes to the listed value | manifest.json files[records.jsonl] | `fb3bb4cb...` | `923bc4cc...` | MISMATCH | sha256 | sha256 of the 642 bytes of records.jsonl |
| 10 | the records chain ends at this head | manifest.json chain_head.chain | `bac3de45...` | `8fea13ce...` | MISMATCH | sha256 chain link (first 32 hex of sha256(prev + row JSON, keys sorted)) | each link recomputed from its row's content, starting at genesis; the stored links break at line 2: chain mismatch |
| 11 | the records hold this many rows | manifest.json chain_head.rows | `4` | `4` | VERIFIED | count | rows of records.jsonl counted |

BROKEN: second reader, 24 claims: 16 VERIFIED, 6 MISMATCH, 2 COULD NOT LOOK (evidence-pack verify: BROKEN)
```

The untampered pack gives every row VERIFIED except the witness row for the
pin, which is COULD NOT LOOK until `--witness` names the pin file, and exit 3;
with the pin file every row is VERIFIED, exit 0.

**From Python.**

```text
import json
from arcaeon.prove.second_reader import second_reader, Report
rep = second_reader("pack", witness="witness.jsonl")
rep.verdict, rep.exit, rep.rows[0].recomputed
Report.from_dict(json.loads(rep.to_json())) == rep   # the JSON round trips
rep.to_markdown(), rep.to_table()
```

**Over MCP.** `evidence_pack_second_reader(pack_path, witness_path=None,
format="json")`: `json` answers the report itself, the same object `--json`
writes; `markdown` and `table` answer `verdict`, `exit` and the text. A
format outside those three is a tool error.

**What it does not show.** A VERIFIED row says the bytes give the value the
pack claims. It does not say the records describe what happened. The witness
row checks a local pin file, whose `independence` is `self_asserted`: the
file's own chain and the exact pin, no more. `system_id` and `provider` are
the builder's own words and get no row.
