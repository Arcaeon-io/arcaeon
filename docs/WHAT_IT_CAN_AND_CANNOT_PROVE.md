# What it can and cannot prove

If your agent's record says it refunded 20 dollars, does that make it so? No. Arcaeon came out of a 911 dispatch floor, where a timeline gets read long after the call, by people who were not there. On that floor, what a record cannot tell you matters as much as what it can. So the limits come first.

The words it answers in (VERIFIED, BROKEN, COULD NOT LOOK and the rest) are explained in [The words](WORDS.md).

## What it cannot prove

### The record and the witness

These are the README's limits, word for word.

- **Tamper-evident, not tamper-proof.** Anyone who can write the file can
  still change it. What they cannot do is change it without the check
  noticing and naming the line.
- **One witness, and we operate it.** The hosted witness at
  witness.arcaeon.io is run by us, the people who make this package. A pin
  there shows your head as it stood when we recorded it; it is not a second,
  unrelated party vouching for you.
- **The daily anchor is a clock, not a party.** The witness anchors its pin
  store to a public timestamp once a day. That fixes when the pins existed.
  It says nothing about whether they were right, and nobody behind it checked
  them.
- **Who ran the witness at the time of a pin is unknown to an outside
  reader.** Today you take our word for who operated it when a given pin was
  made. That stays true until we publish a custody record, and we have not
  yet.
- **Reproducible by us, not yet by you.** Re-running the session behind a
  ledger takes the model, the tool server and their state at the time, which
  whoever ran it has and an outside reader does not. Until there is a way to
  hand that over, the substitute is the proxy's request and response digests:
  every call row `arcaeon proxy` writes carries `args_digest` for the request
  and `result_digest` for the response. Given the bytes, you can check they
  are the ones that crossed the seam; you cannot re-run the call to get them.
- **Truncation.** Cut the most recent rows off and what is left still checks
  out. No chain catches that alone. A pin does: once a witness holds your
  head (row count and chain), a shorter or rewritten log no longer matches it.
- **Truth.** The chain records whatever was written, true or not. To tie a row
  to a fact someone can fetch again, store the fact's digest in the row.
- **Authorship.** Who wrote a row is data in the row, not a signature.
  Someone who rewrites the whole log from the first row can rewrite that too.
  A pin held outside your control is what they cannot move.

### Two tapes of the same work (`reconcile`)

- MATCHED means two recorders agree; a colluding agent side and tool side can
  write two agreeing tapes of a lie.
- A call that crossed neither instrumented seam leaves no row on either tape;
  an agent that never calls, or calls through an unwrapped channel, is
  invisible here.
- Digests compare content (canonical JSON), not bytes: a meaning-preserving
  re-serialization in transit is MATCHED by design.
- Without a witness pin, both tapes truncated or rewritten in agreement still
  match; a pin bounds that to the rows written after it.

### The evidence pack

- It is not a statement that any law or standard is met. The pack is evidence
  toward a record-keeping duty, and it says so once, on its first page.
- It does not show the agent behaved well. It shows what was written was not
  changed after pinning.
- Its one witness is ours, so its `independence` field reads
  `self_asserted` unless something better is proven.
- Who operated the witness when a pin was made is not known to a reader:
  `operator_at_t` reads `UNKNOWN` until a custody record is published and
  anchored.
- It carries a subset of the agent audit trail format, with a re-derived
  chain, and lists what is missing.
- Keeping the pack for any length of time is the holder's job, not the job of
  whoever runs the hosted witness.

### Three kinds of sentence on page one

Every sentence on an evidence pack's README.md ends in one bracket that says
what bears it. README.json, beside it, lists each sentence id, the sha256 of
its text and its class, and `arcaeon evidence-pack verify --json` prints how
many of each the page holds.

- **[bytes]**: a hash over frozen content proves it. The manifest hashes and
  the records chain are this kind. Anyone can recompute them from the files.
- **[order]**: only a commitment made before the act proves it. The witness
  pin, and the build time read against the pin time, are this kind. Without a
  pin nothing in the pack bears it.
- **[asserted]**: no field in the pack carries it. The operator's statement of
  the window and the system, the completeness of the could not look list, and
  that any row is true are this kind. It is the builder's word.

A line holding two sentences carries the weaker class. The class each
sentence may carry is fixed in the code, not in the pack, so a pack that
moves a sentence to a stronger class, or leaves one untagged, is BROKEN and
names the sentence.

A coverage sentence, one that says what the window or the record covers
rather than what the bytes are, is [asserted] unless it is derived, and an
[asserted] sentence must name the falsifier a stranger can run, or it is not
allowed on page one. The falsifier is printed after the class, as in
"[asserted; falsifier: could_not_look.json, ...]", and README.json carries it
as `falsifier` beside the sentence. The operator's window statement is
falsified by the could_not_look.json list and by `arcaeon evidence-pack
verify`, which re-derives the window from records.jsonl. The system id and
the provider have no falsifier in the pack, so theirs says so: none
derivable, compare with the operator's own records. The falsifier of each
sentence is fixed in the code beside its class, so an [asserted] sentence
with no falsifier in README.json, or a falsifier naming a file the pack does
not hold, is BROKEN and names the sentence.

### The second reader (`second-read`)

- It does not show whether a claim holds. Two readers reading one sentence
  the same way for a claim does not make the claim right.
- It does not show the readers share no habits. Two models from one family,
  or one vendor, agree more for that reason alone.
- It does not show who wrote a ledger. Reader ids and providers are what each
  row says about itself.
- Its receipt says nothing to a stranger about when. It is local, with no pin
  and no timestamp anchor.

### The mandate gate (`mandate`)

- The gate records the `who` of a mandate on every row and does not check
  it: the proxy cannot see who is behind the agent.
- It judges tool names and arguments on the one seam it sits on. A call that
  goes around the proxy is not checked and leaves no row.
- Record-only is a record, not a control. Only `--mandate-enforce` stops a
  call, and only on that seam.

### `vet` and `badge`

`vet` and `badge` report what their own checks found in the bytes they read.
They are not a review by a person and not a safety certification.

## What it can prove

- **Nothing was changed in the middle.** An edit, a deletion or a reorder
  breaks every later link. `arcaeon verify` answers BROKEN and names the first
  broken line, or VERIFIED when every link holds.
- **Nothing was cut after a pin.** Once a witness holds your head, a shorter
  or rewritten log no longer matches it, as of the last pin. The longest gap
  between pins is your real exposure.
- **Two tapes line up.** `arcaeon reconcile` answers MATCHED, MISSING or
  ALTERED for each step both tapes were expected to hold, and names the fields
  that differ.
- **Which mandate was in force.** Each mandate row carries the file's hash
  and what the call was checked against.
- **What a second reader saw.** `second-read compare` lines up two readings
  ledgers, files every disagreement with both readings, and counts them as
  two integers.
- **What could not be looked at.** When a file is missing, unreadable or
  empty, the answer is COULD NOT LOOK. It is never a pass and never exits 0.
