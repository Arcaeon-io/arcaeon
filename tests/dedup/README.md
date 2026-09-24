# arcaeon-dedup

**Strip repeated text from an agent's context before it costs you tokens.**
*Pure stdlib. No LLM, no embeddings, no network. Cheap enough to run on every call.*

```bash
pip install arcaeon-dedup
```

## Why

Retrieved chunks, tool outputs, conversation history, and memory stores fill up with
literal repeats — the same doc pulled twice by two retrievers, the same boilerplate
header on every result, a chunk that overlaps its neighbour, the same error line
logged forty times. Every redundant copy is pure token waste, and you pay for it on
**every** call that carries it.

Most "dedup" tooling is built for training corpora, or needs embeddings + a vector DB
to run. For agent context you want something that costs essentially nothing, so you
can put it in front of every context assembly without thinking about it.

`arcaeon-dedup` uses **SimHash** to find candidate pairs fast, then **verifies every
candidate by direct feature overlap** before it drops anything. The verification step
is the whole safety story — see below for why a bare similarity threshold is not one.

## Use

```python
from arcaeon_dedup import dedupe

doc = "Docs: the API returns 200 on success. See the reference for details."
chunks = [
    doc,
    doc.replace(". ", ".  "),      # same doc, refetched — whitespace noise only
    "The database connection timed out after 30 seconds.",
]

kept, report = dedupe(chunks)
# kept   -> 2 items (the repeat dropped, order preserved)
# report -> deduped: kept 2, removed 1 repeat(s); ~69 chars / ~17 tokens saved
```

Tuning:

```python
dedupe(chunks, min_overlap=0.95, max_hamming=12, k=1, keep="first")
```

- `min_overlap` (default **0.95**): the verification gate. A candidate pair is only
  dropped if its measured feature overlap — the *minimum* of character-4-gram and
  word-bigram Jaccard, after normalizing case, punctuation, and whitespace — is at
  least this. `1.0` drops only exact matches after normalization. Below ~0.7 you are
  deleting content that is merely *related*, which is silent data loss.
- `max_hamming` (default **12**, of 64 bits): how wide the *candidate* net is thrown.
  Raising it finds more candidates to verify; it does **not** weaken the gate above.
- `k` (default **1**): SimHash shingle size, candidate generation only.
- `keep`: `"first"` keeps the earliest of each cluster (best for chronological
  context — the original stays); `"longest"` keeps the fullest phrasing. Clusters are
  formed against fixed representatives, so nothing is ever dropped against an item it
  wasn't verified against.

Also exported: `simhash(text)`, `hamming(a, b)` if you want the primitives directly.

## What it removes / what it will not

**Removes:** near-verbatim repeats. Identical text; text differing only in whitespace,
case, punctuation, or wrapper noise; the same passage retrieved twice. That is the
common and expensive case, and it is the one this can do safely.

**Will not: collapse paraphrase — and it must not pretend to.** No lexical distance
separates "reworded, same meaning" from "one word changed, opposite meaning."
`Charge the customer $19` and `Refund the customer $19` are lexically **closer** than
any two honest paraphrases of the same sentence. So are `Alice owes Bob $100` and
`Bob owes Alice $100` — identical bag of words, opposite fact. Any setting aggressive
enough to collapse a paraphrase deletes those too, and deleting those is deleting
facts out of an agent's context with a report that says it saved you tokens. If you
need paraphrase collapsed, that requires semantics: use embeddings.

**The one thing it can still get wrong**, stated plainly rather than left for you to
find: a single inserted or substituted token inside a **long** document leaves the two
strings overwhelmingly identical, so past some length a one-word change reads as a
repeat. No threshold fixes this in general — it is the same theorem as above. If
one-token inversions are load-bearing in your corpus (medical, legal, financial
records), pass `min_overlap=1.0` and drop only exact matches.

**Collapse is order-dependent by design.** Items are clustered greedily against
the first representative they match (single-linkage). If A matches B and B
matches C but A does **not** match C, then feeding `[A, B, C]` keeps A and C
while `[B, A, C]` collapses both into B — the *same* set of inputs yields a
different survivor count depending on order. Every drop is still verified
against the representative it was dropped for, so no item is removed against
something it wasn't measured against; but if your pipeline merges retrievers in
arbitrary order and you need order-stable output, sort the input first or run at
`min_overlap=1.0`.

MIT. Built by [Arcaeon](https://arcaeon.io) — the evidence layer for AI.
