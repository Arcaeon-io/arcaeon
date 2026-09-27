# The second reader

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
`POST /v1/second-read/compare`.
