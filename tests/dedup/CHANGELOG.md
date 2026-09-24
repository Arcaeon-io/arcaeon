# Changelog — arcaeon-dedup

## 0.1.5 — 2026-09-01 (sell-code audit: content-empty items now honor the whitespace promise)

Full-read audit of source, tests, README, and pyproject ahead of a code
sale. One finding, LOW, fixed; everything else checked clean (list below).

- **Fixed — strings with no word content collapsed only when BYTE-identical,
  so `""` vs `"\n"` and `"🔥"` vs `"🔥 "` survived as two items.** The 0.1.2
  symbol-only fix (correctly) stopped all emoji/symbol-only items from
  collapsing into one by requiring identity when both sides normalize to
  empty — but it compared RAW bytes, so a trailing newline or space made an
  empty tool result its own duplicate's twin. That contradicts the README's
  "differing only in whitespace ... collapse" claim, which held for every
  string WITH word content and silently did not for these. `_overlap` now
  folds whitespace runs (`" ".join(s.split())`) before the identity check on
  the content-empty branch — the same treatment `_normalize` gives word
  content — and still compares symbol content exactly, so a 5-star and a
  1-star rating remain distinct and a space BETWEEN symbols is still a
  boundary. Repro before the fix: `dedupe(["", "   ", "\n"])` kept 3;
  `dedupe(["🔥", "🔥 "])` kept 2. Regression:
  `test_content_empty_items_differing_only_in_whitespace_collapse` (with
  both distinct-symbol controls). Suite 47 → 48.

Checked and clean: no file I/O, no deserialization, no eval/exec, no
recursion (deep-nesting immune); lone UTF-16 surrogates (`"\ud800"`) pass
through `_normalize` as non-word chars and never reach `.encode()` in
`_feature_hash`; NaN/int/bool knobs are refused by the existing validation;
`__version__`, `pyproject.toml`, and this changelog agree (no CLI, no
`--version` to drift). The pass-1 quadratic cost disclosed in 0.1.4 (F5)
remains disclosed and unchanged.

## 0.1.4 — 2026-08-24 (F1: min_overlap=1.0 now means exactly what three surfaces say it means)

Adversarial audit finding (HIGH), same-day fix. `min_overlap=1.0` is
documented on the README (twice, including the paragraph aimed at
medical/legal/financial corpora) and the `dedupe` docstring as "drops only
exact matches after normalization." Delivered was weaker: identical
normalized FEATURE SETS scored 1.0, and a periodic string saturates both
gram sets — so "word word" vs "word word word" collapsed at the exact-only
setting, silently losing the repeat count ("3 retries" vs "2 retries"),
which in the routed domain is the fact. The module docstring had the honest
wording all along; the other two surfaces promised more.

Fix in `_overlap`: 1.0 is now reachable only when the normalized STRINGS
are equal; identical-feature-set non-identical strings cap at 0.9995, so
they still collapse at every practical default threshold while the
exact-only setting keeps its word. Planted red + both green controls
(a genuine normalized-exact duplicate still collapses at 1.0; the periodic
pair still collapses at defaults). Mutation-verified.

Also from the same audit: the keep='longest' contract test was VACUOUS —
its fixture never clustered at default thresholds, so its only real
assertion loop never ran and the test passed with the feature entirely
disabled. Rebuilt with an empirically measured clustering fixture and a
fixture guard that refuses to pass when nothing clusters (the guard caught
the first rebuild too). The manual runner's hardcoded test count replaced
with a computed one. Suite 46 → 47.

Known, disclosed, unfixed (audit F5, LOW): pass-1 recomputes normalization
per comparison — quadratic degradation on multi-thousand-chunk inputs
(measured 2.6s at n=2000). Context-assembly sizes are unaffected.

## 0.1.3 — 2026-08-16

Hypothesis property-test pass, same night as `arcaeon-continuity`,
`arcaeon-ledger`, and `arcaeon-distill` (ledger found a real `splitlines()`-vs-
`ensure_ascii=False` false-mismatch bug on the U+0085/U+2028/U+2029
unicode-line-separator class). **Verdict for this package: that bug class is
STRUCTURALLY ABSENT.** `arcaeon_dedup` has zero file I/O anywhere in the
package (`grep -n "open(\|jsonl\|splitlines\|readlines"` returns nothing) —
it is a pure function over an in-memory `list[str]`, so there is no
write-then-read-back path for that bug to live in. New property tests
(`test_hypothesis_dedup.py`, 32 tests) confirm the class is at least handled
without crashing and deterministically wherever it does reach the package
(`_normalize`, `simhash`, `dedupe`).

One real bug turned up and was fixed:

- **Fixed (H-dedup-1) — `_normalize` used `.lower()`, not `.casefold()`, so
  German eszett case variants were never even considered as duplicates.**
  `"straße".lower()` stays `"straße"`, but `"STRASSE".lower()` is `"strasse"`
  — different word tokens, so `dedupe(["die straße", "DIE STRASSE"])` kept
  both, contradicting the package's own documented claim that content
  "differing only in ... case ... collapse[s]." Found by
  `test_whitespace_case_punctuation_variant_always_collapses`. Fixed by
  switching to `str.casefold()`, the Unicode-standard case-insensitive
  comparison primitive (`"ß".casefold() == "SS".casefold() == "ss"`); for
  plain ASCII text this is identical to `.lower()`, so nothing else changes
  (confirmed: existing 9-test suite unchanged; see the full test count below).
  Regression pin: `test_eszett_case_variant_now_collapses_h_dedup_1`.

- **Investigated, NOT a bug — Turkish dotless-ı (U+0131) still doesn't
  unify with "I"/"i".** Same property test also found
  `dedupe(["ıstanbul", "ISTANBUL"])` keeps both. Root cause: Turkish casing
  is locale-DEPENDENT (`ı<->I`, `i<->İ`), and Python's `str.upper/lower/
  casefold` implement only the locale-independent default tables, where
  `"ı".upper() == "I"` but `"I".casefold() == "i" != "ı".casefold() == "ı"`.
  A real fix needs a Turkish-aware casing table (e.g. PyICU), which
  contradicts this package's zero-dependency, pure-stdlib design point —
  left as an accepted, documented boundary, not chased. Pinned by
  `test_turkish_dotless_i_is_accepted_out_of_scope` so a future run reads it
  as known, not rediscovers it as a surprise.

Also added, from the same mutation-testing pass, five regression tests that
caught surviving mutants without finding a live bug: `_overlap`'s combining
rule really is a `min` (AND-gate) not a `max` (OR-gate) between the
char-gram and word-bigram views; `_jaccard(set(), set())`'s documented
"both empty = identical" contract is pinned even though every current caller
already guards around it; `keep="longest"`'s tie-break really does prefer
the earliest occurrence, not the latest, when candidates are equal length;
`simhash`'s bit-decision rule is strictly `> 0` (an exact-zero vote sum
stays unset, not `>= 0`); and the SimHash candidate gate's own boundary
(`hamming == max_hamming`, admitted, not excluded) holds on a real pair
engineered to land exactly on it.

**Fixed — test_dedup.py's `sys.path.insert` used a hardcoded absolute path**
(`arcaeon-dedup`), so the suite only ran correctly from that
exact machine/checkout. Switched to
`sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))`, which
resolves relative to the test file itself — portable to any checkout path.

Test count: **9 → 46 passed** (14 in `test_dedup.py` + 32 in
`test_hypothesis_dedup.py`; all pre-existing tests still pass unmodified).

## 0.1.2 — published to PyPI 2026-08-15

Emoji/symbol-collapse fix, found while writing the order-dependence note below.

- **Symbol-only and emoji-only items no longer all collapse into one.** `_overlap()`
  builds its Jaccard score from character-4-grams and word-bigrams, both of which
  come from `\w+` word matching. Emoji, star-ratings, and other symbol-only strings
  normalize to an EMPTY feature set (`_normalize` finds no words), so every such
  pair read `_jaccard(empty, empty) == 1.0` — maximum overlap, guaranteed collapse,
  regardless of which symbols they actually were. A five-star rating and a
  one-star rating, a rocket emoji and a heart emoji, silently became "the same
  item" and one was deleted. Fix: when BOTH sides normalize to empty, overlap is
  now 1.0 only if the RAW strings are byte-identical, 0.0 otherwise — the only
  defensible "duplicate" with zero word content to compare is an exact repeat;
  anything else is content we cannot measure, so it is kept, not guessed.
- **New regression test** (`test_symbol_only_items_are_not_all_collapsed`): five
  distinct emoji/star/punctuation-only items must all survive `dedupe()`; two
  byte-identical emoji items must still collapse to one; empty-string items still
  collapse together while real content next to them is kept. 9/9 tests pass.
- **README addition: collapse is order-dependent by design.** Documented, not
  changed — clustering is greedy single-linkage against the first representative
  a candidate matches. If A matches B and B matches C but A does not match C,
  `[A, B, C]` keeps A and C while `[B, A, C]` collapses both into B: the same
  input set, different survivor count, depending on feed order. Every drop is
  still verified against the specific representative it was measured against, so
  nothing is removed against an item it was never compared with — but a pipeline
  that merges retrievers in arbitrary order and needs order-stable output should
  sort the input first, or run at `min_overlap=1.0` (exact-match only).
- **Version:** `__version__` and `pyproject.toml` bumped 0.1.1 → 0.1.2 locally.
  Held for the 2026-08-15 2 PM publish batch (rebuild dist from this source,
  clean-venv install, re-run discriminator, then `twine upload`) — not published
  to PyPI yet. products.yaml stays at 0.1.1 (PyPI's live version) until publish;
  do not advertise 0.1.2 on the site before it is live.

## 0.1.1 — 2026-08-14 (verify before deleting — 0.1.0 was dropping facts, not duplicates)

Hostile audit. At stock defaults the library silently deleted content that was
NOT duplicated, at these rates: 95.7% of 10-word items differing in one word,
99.7% at 20 words, 99.9% at 30 words; roughly 1 collision per 500–2000 documents
sharing zero words. Concretely, these all collapsed to one item and the report
called it a saving: "Alice owes Bob $100." / "Bob owes Alice $100." (hamming 0);
"Transfer 500 from savings to checking" / "...from checking to savings"; "The
patient is allergic to penicillin" / "...is NOT allergic..."; "Charge the
customer $19" / "Refund the customer $19"; three distinct patient records; four
distinct payment-decline log lines.

- **Cause:** SimHash was used as the VERDICT, not a filter. `k=1` makes the
  fingerprint a bag of words, and bit-summing is commutative, so any permutation
  of the same words lands at Hamming distance 0 — unreachable by any threshold.
  `max_hamming=12` over 64 bits is a ball wide enough that documents sharing no
  words at all can land inside it.
- **Fix:** SimHash still generates candidates; a candidate is now dropped only if
  MEASURED feature overlap clears `min_overlap` (default 0.95) — the minimum of
  character-4-gram and word-bigram Jaccard over normalized text. Two views,
  because bigrams carry the word order that catches Alice/Bob, and char-grams
  keep short strings and space-free scripts measurable. After the gate: 0/300
  dropped at 10/20/30/60 words with one word changed; 0 collisions across 1200
  independent documents; verbatim/whitespace/case/punctuation repeats still
  collapse.
- **Honest rescope:** this is a NEAR-VERBATIM deduper, stated in the README
  rather than left to be found. It does not collapse paraphrase and must not
  pretend to — no lexical distance separates "reworded, same meaning" from "one
  word changed, opposite meaning," and any setting that collapses the first
  deletes the second.
- **Also fixed:** `keep="longest"` mutated the cluster representative mid-scan,
  so membership chained transitively and items were deleted against a
  representative they were never compared with (now two passes, frozen
  representatives). `k=0` bypassed the length guard and collapsed the entire
  input to one item (now raises `ValueError`). A bare string was silently
  deduplicated character by character; `None`/int/bytes entries raised
  `AttributeError` from three different layers (now typed `TypeError`).
  CJK/Thai text was one `\w+` token, so SimHash degenerated to a plain hash and
  detection silently stopped (char-grams now cover it). NFKC normalization
  added.
- **Remaining limitation, stated rather than hidden:** one token changed inside
  a LONG document still reads as a repeat past some length — same theorem;
  `min_overlap=1.0` is the exact-only escape hatch.
- Test suite rewritten. The 0.1.0 suite asserted only that dedup FIRES — not one
  assertion that a distinct item survives — which is why it passed on all of the
  above. 9 must-survive pairs became the load-bearing tests (later 9→10 with the
  0.1.2 symbol-only regression).

## 0.1.0 — 2026-08-13 (initial build)

Token-saving primitive from the 2026-08-13 research: strip near-duplicate text
before it hits the context window. Pure stdlib SimHash, zero dependencies, no
LLM, calibrated defaults. The cheapest-to-run whitespace pick.
