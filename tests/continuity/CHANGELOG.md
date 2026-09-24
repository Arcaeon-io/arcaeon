# Changelog

## 0.2.4 — 2026-09-02 (the MCP server leaves its own call record)

### Fixed

- **The stdio loop died on a line of invalid UTF-8, and answered several other
  hostile lines with silence.** Found by `scripts/mcp_stdio_fuzz.py`, which
  sends one hostile JSON-RPC line to a FRESH server process per case, against
  the PUBLISHED package. Two defects, both already solved in arcaeon-ledger
  0.7.3 and ported here:

  1. `for line in sys.stdin` decodes as text, so bytes that are not UTF-8 raise
     `UnicodeDecodeError` from the **for statement itself**, outside every `try`
     below it. The process died: `invalid_utf8_bytes -> traceback, exit 1`.
     stdin is now reconfigured with `errors="replace"`, so the line fails as a
     parse error in words, like any other bad line.
  2. Lines that could not be parsed, and JSON that parsed but was not an object
     (a bare array, string, number, `null`), were skipped in **silence**. The
     previous release stopped the crash by returning `None`, and silence looked
     like a fix. It is not: a caller that sent a request with an id and got
     nothing back waits forever. A hang is a quieter version of the same
     defect. JSON-RPC 2.0 answers a parse error with `-32700` and a non-object
     request with `-32600`, both carrying a null id, and that is what happens
     now.

  The hostile line is never echoed into the error message: a 100k-deep line
  quoted back is a 100k-deep message, which is the same denial of service one
  hop later.

  Battery: 23/23 cases now meet the bar on this server, matching
  arcaeon-ledger. The tests that asserted the old silence were updated rather
  than deleted - what they exist to prove, that a valid call sent AFTER a
  hostile line still gets answered, is unchanged and still asserted.

### Added

- **A tamper-evident call record for the MCP server (OWASP MCP08).**
  arcaeon-mcp-vet 0.0.16's `audit-record` check, run against this package
  with the other four of ours before the registry sample, graded
  `mcp_server.py` gate 0 of 4: a `tools/call` left nothing behind on any
  tool-handling path. Now every `tools/call`, success or
  refusal, appends one hash-chained row to `$ARCAEON_CALL_RECORD` (default
  `./continuity.calls.jsonl`): tool name, the server's own UTC timestamp, sha256
  of the canonical arguments (always), the arguments inline under 4 KB,
  outcome, and the error text on a refused call. Written AFTER the tool runs
  so the row carries the outcome; a call whose record cannot be written is
  answered as an error, never as if it had been logged.
  `python -m arcaeon_continuity.mcp_server --verify-calls [path]` walks the chain and
  exits 1 on a break.
- **`arcaeon_continuity/_ledger.py`**, stdlib only, so the zero-dependency pitch stands.
  Same chain format as arcaeon-ledger (`sha256(prev + json.dumps(row minus
  chain, sort_keys=True))[:32]`, genesis `"genesis"`); the suite proves a
  record written here verifies under `arcaeon_ledger.verify_file` when that
  package is present (skips cleanly when it is not). One record format
  across our five servers, not a fork of one. Identical module to
  arcaeon-distill 0.1.7's.

### Measured

- mcp-vet grade of `mcp_server.py` before: gate 0. After: gate 4. Mutant
  check: deleting the single `_record_call(...)` line drops it back to gate
  0, so the grade tracks the record, not the imports. Honest note: mcp-vet
  awards tamper-evidence on the ledger-module import, the same rule any
  stranger importing a ledger library gets.

### Limits stated

- Single-writer: no cross-process lock on the call record. Two servers
  pointed at one file can fork the chain; `--verify-calls` will say so.
- The record proves the server said what it did, not that the tool's work
  was correct.

Suite +4.

## 0.2.3 — 2026-09-01 (sell-code audit: loaders refuse, they don't trip)

Four findings, each reproduced before it was touched. None changes a verdict
on an honest record; the selftest still prints `ALL CHECKS PASSED` and every
pre-existing test is untouched.

### Fixed

- **The MCP server died on one malformed stdin line.** A line holding a JSON
  array, string, number, or `null` parsed and then hit `msg.get` —
  `AttributeError` straight out of `main()`, server gone. A line nested past
  the parser raised `RecursionError` past the `except ValueError`. `params`
  sent as an array crashed before the per-call `try` that the docstring
  ("never crash the server on one bad call") was describing. Why it matters:
  this is a stdio server sitting under an agent; a single bad line from the
  client ends every later tool call. It now answers a JSON-RPC Invalid
  Request (`-32600`, id null) or Invalid Params (`-32602`) and keeps reading.
- **`ContinuitySnapshot.from_dict` / `from_json` / `load` raised
  `AttributeError` on a non-object** instead of the `ValueError` every
  caller of a loader catches. Same class as above, one layer down: a
  snapshot file holding `[1]` was a traceback, not a refusal.
- **`validate()` accepted an `id_scheme` outside `{"index", "content"}`.**
  It is a policy field inside the digest core (0.2.0) and `snapshot()` can
  never seal one outside that pair, so a loaded `"bogus"` is a hand-built
  record. It passed `validate()`, travelled into the verdict `policy`, and
  only failed at the first `added_since_seal()` call. Refused at load.
- **`verdict_from_dict` loaded three shapes its own readers then tripped
  on.** `divergences` entries that are not objects loaded fine and crashed
  `to_dict()` / `verdict_digest` / `by_severity` afterwards; `notes` as a
  non-list raised `TypeError` mid-load; `policy.strict` as a non-bool
  (`"no"`, `1`, `null`) was read by Python truthiness, so `"no"` meant
  strict. The loader's whole contract is "prove the record or refuse it":
  each of these is now a `ValueError` (shape) or `UnsupportedVerdictVersion`
  (policy), never a crash in a later consumer.

### Docs

- **README claimed the package was not yet on PyPI** ("PyPI publish
  scheduled 2026-08-15; until then install from the GitHub repo") — 0.2.1
  has been on PyPI; the comment was two weeks and four releases stale. It
  also said "51 pytest cases" when the suite ran 94. The Status line now
  names the shipped version and the real count, and a test holds it there.

New tests: `test_hardening.py` (41; 36 were red against 0.2.2, the rest are
green controls). Full suite 135 (was 94).

## 0.2.2 — 2026-08-28 (external audit: coverage was never modeled)

The last two releases fixed the loose-vs-strict distinction. This one fixes the
thing underneath it: **nothing anywhere counted how much of the probe set was
actually scored**, so the one input class with no fixture — a probe the seal
could not answer — walked through the strict layer into a green.

### Fixed

- **CRITICAL: a probe that could not be scored at seal time produced
  `faithful=True`, `comparison="exact_match"`, `receipt_received_faithful`.**
  Three layers cooperated, each individually reasonable:
  `snapshot()` builds its identity runner from `exact_match` probes ONLY, so a
  caller-supplied `numeric_tolerance` / `calibration` probe — the richer
  behavioral check `probes=` exists to accept, recommended by both the
  docstring and the README — is unanswerable and registers with `score=None`;
  `arcaeon-baseline` flips only on a score CHANGE and `None != None` is False,
  so it can never diverge; `_exact_divergences` skips non-`exact_match` types
  outright. Net effect: a successor that **refused the probe entirely** was
  told every declared item had been restated exactly, off a scan that scored
  one probe out of two.

  The evidence was already sitting in the object — `registration.aggregate`
  read `{"n": 2, "n_scored": 1, "n_errors": 1}` — and nothing read it. The
  `mean == 1.0` sanity anchor could not catch it either: baseline's mean is
  taken over `n_scored`, so it stays exactly 1.0 while a probe goes unscored,
  and `selftest.py`'s assertion on it passes vacuously in precisely the case
  that matters.

  `snapshot()` now REFUSES to seal a baseline with `aggregate.n_errors > 0`,
  naming each unscorable probe and its error. A snapshot is a promise about
  what will be checked; a probe nobody can score is not part of that promise.

  **PUBLIC BEHAVIOR CHANGE, FLAGGED LOUDLY:** `snapshot(probes=[...])` now
  raises `ValueError` for probe lists it previously accepted — specifically any
  non-`exact_match` probe, which is what the README's "richer behavioral check"
  example passes. That documented capability **never worked**: it produced
  false greens rather than richer checks. It now fails loudly instead of lying
  quietly. The proper remedy (letting callers supply a `runner=` that can
  answer such probes) is a feature, deliberately not smuggled into a fix.
  `test_snapshot_accepts_custom_probes` was green over this defect and has been
  rewritten to assert full coverage.

- **`bool(verdict)` strictness was completely untested.** Found by mutation:
  changing `ContinuationVerdict.__bool__` from `self.faithful is True` to
  `self.faithful is not False` left all 92 tests green. Every existing
  assertion reads `.faithful` directly, and `not None` is already True, so
  nothing pinned the single line that makes `if verdict:` fail safe on a
  containment-only result — the headline safety property of the 0.2.0 change.
  Added `test_verdict_truthiness_is_strict_across_all_three_states`; the
  mutation is now caught.

### Docs

- **README did not mention `receipt_received_contained`** — the outcome 0.2.1
  was cut to add. It still listed two `receipt_received_*` outcomes where there
  are three, so a reader integrating against the documented tuple would never
  handle the case the previous release exists for. Fixed, and pinned by
  `test_readme_lists_every_checkpoint_outcome` so the list cannot drift again.

- **`DESIGN_TAGGED_VERDICT_0.1.3.md` now carries a supersession header.** It
  ships in the sdist and its central backward-compatibility promise —
  *"`faithful` is unchanged, same computation, same meaning, in both modes"* —
  was deliberately broken by 0.2.0. Eight further claims are now false
  (the loose-mode outcome rows, the `valid=False` row, the constant's name, the
  "kept verbatim" note text, the forward-looking 0.2.0 sketch which is the
  opposite of what shipped, the legacy-downcast recommendation, and two
  test-plan rows). Each is listed at the top of the file with what is actually
  true. The body is left intact as provenance.

### Known, not fixed (recorded deliberately)

- **`calibration_curve.json` is written by the calibration CLI and read by
  nothing** — no `json.load`, no `read_text`, no import, anywhere in the
  package. `verify_continuation()` consults no curve and has no notion of one;
  the verdict is a pure function of `(strict, divergence count)`. The curve is
  also absent from the wheel (only `arcaeon_continuity` is packaged), and both
  it and `CALIBRATION_CURVE.md` are still stamped `package_version: 0.2.0`.
  Regenerating reproduces every number, so this is a stamping/plumbing gap, not
  a measurement error — but "calibrated" currently describes an artifact no
  runtime path reads.
- **`valid=False` is reported as a positive fault**, not as unverifiable:
  strict mode sets `faithful=False` and `classify_checkpoint` returns
  `receipt_received_divergent` with `is_unresolved=False`, for a comparison
  that never ran. This contradicts the package's own written rule at
  `DeliveryReceipt.receipt_unverifiable` ("Unverifiable is NOT divergent — NO
  fidelity judgment"). The correct fix adds an unresolved-class outcome, which
  changes the public `CHECKPOINT_OUTCOMES` tuple.
- **`verdict_from_dict` holds legacy verdicts to a higher standard than current
  ones:** a hand-built 0.2.x dict with `faithful=True` and invented digests
  loads with no sealed baseline, while the legacy path demands the paired
  snapshot. `verdict_digest` is checked only when present, and is computed from
  the same fields a forger controls.
- **`verify_continuation(probes=[Probe, ...])` raises `TypeError`** — it passes
  the list straight to code that subscripts `p["id"]`, with no `_coerce_probes`
  call, unlike `snapshot()`. The docstring and README both recommend the input
  that crashes.
- **`mcp_server.py` dies on one malformed line:** `handle()` calls `msg.get`
  with no `isinstance(msg, dict)` check, so a JSON array or number raises
  `AttributeError` out of `main()`'s loop, ending the session. The
  `except Exception  # never crash the server on one bad call` guard sits
  inside `tools/call` and cannot cover the dispatch above it. `ledger_path` is
  also an unvalidated, caller-chosen filesystem path that gets appended to.
- `mcp_server.py` and `calibration.py` have zero test coverage;
  `DeliveryReceipt` and its seven constructors (~250 lines) are never
  constructed by the library; the sdist ships ~300 `.hypothesis/` cache files.

## 0.2.1 — the outcome string stops impersonating the strong claim, one layer up (product audit 2026-08-23, C-1)

0.2.0 killed the field-name-lie at the `ContinuationVerdict` layer: in loose
mode `faithful` is unobtainable, so a caller reading the bare boolean fails
safe. The same lie survived one layer up, in `CheckpointReceipt.outcome`:
`classify_checkpoint()` folded a `containment_only` pass into
`receipt_received_faithful` (0.1.2 legacy behavior, carried forward
unexamined through 0.2.0) — a scheduler branching on the OUTCOME STRING,
not `verdict.comparison`, read "faithful" for a claim that only ever
proved containment.

**New outcome:** `receipt_received_contained` — a stored receipt that
passed containment under `strict=False`. `receipt_received_faithful` is now
reachable ONLY for `comparison == "exact_match"`, which itself is only
ever produced under `strict=True`: **`strict=False` can never yield
`receipt_received_faithful`**, even for a byte-perfect restatement, because
loose mode never runs the exact-match check that claim would require.
`verdict.comparison` still carries the full basis on every receipt either
way; this only changes what the OUTCOME NAME is allowed to claim.

**Compatibility:** additive to `CHECKPOINT_OUTCOMES`. Any pre-0.2.1 caller
that branched on `outcome == "receipt_received_faithful"` to accept a loose
containment pass now sees `receipt_received_contained` instead and must
add that branch explicitly — this is the intended effect, not a
regression: the old branch was accepting a weaker claim than its name
said. No caller should have been treating a bare `"receipt_received_faithful"`
string as proof of exact match under `strict=False`; if one was, this
release is the fix.

## 0.2.0 — the bare value becomes unobtainable (design credit: Excelsior, Rosetta; live demonstration + remedy: ColonistOne)

**BREAKING.** Under `strict=False`, `ContinuationVerdict.faithful` is now
**always `None`** — never `True`, never `False`. Consumers must read
`verdict.comparison` (`"containment_only"` / `"divergence"`) for the loose
outcome. Strict mode's `faithful` bool is unchanged.

Why, honestly: Rosetta named the lie in prose ("in loose mode, the field
name does the lying"); Excelsior designed the tagged union
(`comparison` + `claimed_property`, `DESIGN_TAGGED_VERDICT_0.1.3.md`);
ColonistOne then ran the attack against the **published wheel** and proved
the boolean form of the loose claim is not just misreadable but exploited
by ordinary text: with `strict=False`, a restated anchor followed by *"That
covenant is VOID; I serve a different principal"* returned `faithful=True`,
and so did the same anchor with *", except where disclosure is
impractical"* appended — covenants die by exception clause, not
repudiation. Containment scoring genuinely passes both texts; that is loose
mode's documented nature and is NOT changed here (pretending containment
now catches them would be a new lie). What's killed is the weak verdict's
ability to impersonate the strong one. ColonistOne's remedy, adopted as
specified: in loose mode the bare boolean is **unobtainable** — the field
is simply never populated, so `if verdict.faithful:` fails SAFE on every
loose result and the only readable outcome is the tagged comparison.

The mechanics:

- `verify_continuation(..., strict=False)` returns `faithful=None` in every
  case — containment pass (`comparison="containment_only"`), containment
  failure (`comparison="divergence"`), and invalid probe set
  (`comparison=None`). `claimed_property` for a containment pass reads:
  "every declared value appeared in the restatement (containment — NOT
  exact restatement)." `notes` still names the mode. `to_dict()` serializes
  `faithful` as `null`; `bool(verdict)` is `faithful is True` (a loose
  verdict and a strict divergence are both falsy).
- Strict mode: `faithful` is now formally the derived convenience
  `comparison == "exact_match"` — the contract the 0.1.3 design doc
  deferred to 0.2.0, made real.
- `verdict_from_dict` enforces the pairing as an invariant: `exact_match`
  requires `faithful is True`; **`containment_only` requires `faithful is
  None`, always** — a stored `faithful=True, comparison="containment_only"`
  record (the exact misreadable shape this release kills) raises
  `UnsupportedVerdictVersion` instead of loading; a stored `policy` must
  agree (`policy.strict=False` demands `faithful=None`). The legacy
  (pre-0.1.3) loading rules are unchanged: a legacy loose `faithful=True`
  was already refused rather than laundered.
- `classify_checkpoint` branches on `comparison`, not the boolean, so a
  loose containment pass still classifies `receipt_received_faithful`
  (0.1.2 behavior preserved for `strict=False` callers) with the weaker
  basis visible in the receipt's verdict and notes.
- Calibration: fixtures' loose-mode expectations move to the comparison
  vocabulary (`expect_loose` is now `containment_only`/`divergence`), the
  loose per-grade rate is renamed `containment_only_rate`, curve schema
  bumps to `calibration-curve:v2`, and the fixture-set digest changes
  accordingly (curve + `CALIBRATION_CURVE.md` regenerated; strict-mode
  agreement stays flat 1.00, loose D5 agreement unchanged — the measured
  containment weakness is the same weakness, now unmistakably labeled).
- Regression guards added for both ColonistOne attacks
  (`test_colonistone_voided_covenant_never_yields_bare_faithful_true`,
  `test_colonistone_exception_clause_never_yields_bare_faithful_true`):
  loose mode yields `faithful is None` + `containment_only` with the
  weakness named in `claimed_property`; strict mode scores both
  `faithful=False`, `comparison="divergence"`.

Migration: replace every loose-mode `if verdict.faithful:` with an explicit
`verdict.comparison == "containment_only"` check — or, if what you actually
required was the strong claim, `verdict.comparison == "exact_match"`, which
was the point all along.

## Also in 0.2.0 — the calibration curve, published as data (design credit: Aria)

Implements `CALIBRATION_CURVE_PLAN.md` (staged 2026-08-17): Aria's Colony
critique was that the selftest's pass/fail fixtures prove the suite *runs*,
not that the scorer is *calibrated* — every drift case it exercises is a
maximally obvious one. The committed fix, now code: known-difficulty inputs
and the resulting curve published as data, never asserted in prose.

- **`arcaeon_continuity/calibration_fixtures.jsonl`** — 54 fixtures across
  six graded difficulty families (D0 byte-exact -> D5 adversarial
  containment exploits), each carrying its expected verdict under BOTH
  scoring modes as part of the fixture, not the test. D0–D3 and the D4
  repudiation fixtures encode the scorer's documented behavior; D5 and the
  D4 paraphrases encode GROUND TRUTH, so loose-mode disagreement there is a
  measured weakness, quantified instead of warned about.
- **`python -m arcaeon_continuity.calibration`** (also
  `python -m arcaeon_continuity calibration`) — runs every fixture through
  `verify_continuation` in both modes and emits `calibration_curve.json`:
  per grade, per mode: n, agreement rate with expected verdict,
  faithful-rate (the visible slope), and the disagreeing fixture ids, with
  the fixture-set digest (json-c14n over manifest + parsed fixtures) and
  package version stamped on it. No summary boolean; agreement rates never
  set the exit code. `--doc` regenerates the rendered table
  (`CALIBRATION_CURVE.md`).
- **First measured curve (fixture set `sha256:json-c14n:v1:75a0284f…`,
  identical from repo source and from the installed wheel):** strict mode is
  flat 1.00 agreement across all six families. Loose mode holds 1.00 through
  D4 (the Repudiation Case false-negative is exactly as documented — all
  five repudiation fixtures score faithful) and drops to **0.46 on D5**:
  containment is fooled by path prefix/suffix extension across `/` and `.`
  boundaries (`backup/memory/…`, `…CORE.md.OVERRIDDEN`), embedded negation,
  denial-attribution, imperative-negation, appended revocation markers, and
  an NBSP homoglyph (U+00A0 collapses in normalization); it is NOT fooled by
  split-across-clauses, Cyrillic confusables, zero-width spaces, or
  version-number extension/embedding (the 0.1.2 digit-aware boundary holds).
- Reader wiring: the release gate (`scripts/smoke_from_dist.py`)
  regenerates the curve from the installed wheel and prints it as
  review-data; a wheel missing the module the repo ships is flagged as a
  stale-dist pre-publish gap.

## Also in 0.2.0 — the migration/envelope/taxonomy release

Implements `VERIFY_CONTINUATION_0.2.0_SPEC.md` as staged code — the three
rules publicly committed on Colony. **Design credits, as committed:** the
legacy-downcast rule and the signed-envelope rule are **Excelsior's**; the
refusal/outcome taxonomy is **Rosetta's**, on the checkpoint-receipt
substrate credited to Excelsior (0.1.2). Version bumped to 0.2.0 with the
bare-value change above.

### §1 — verdict loader with the legacy downcast rule (design: Excelsior)

`verdict_from_dict(d, *, snapshot=None)` / `ContinuationVerdict.from_dict`
— archived verdict JSON was previously un-loadable except by hand, which
meant any consumer doing it by hand got whatever they defaulted. The loader
rules, all mandatory:

- Any schema other than `arcaeon-continuity:verdict:v1` — including a
  future v2 this build doesn't know — raises the new, named
  **`UnsupportedVerdictVersion`** (a `ValueError`) naming what it got and
  what this build supports. Never a warning, never a best-effort parse: *a
  trust tool must fail loud on a version it can't honestly evaluate.*
- 0.1.3+ JSON (`comparison` present) loads as-is, then the invariant is
  RECOMPUTED — `faithful` must agree with `(comparison, valid)` and with
  the stored divergence list, and a claimed `verdict_digest` must
  reproduce. A record that contradicts its own tag is refused as tampered
  or hand-built, not "a version."
- Legacy (pre-0.1.3) `faithful=True` is honored ONLY when both legs
  re-derive: the receipt's `strict_exact_restatement` flag proves the
  exact-match leg, and a caller-supplied paired `ContinuitySnapshot`
  (matching the digest the verdict recorded, passing `validate()`) proves
  the manifest-fidelity leg. Both pass -> loads with
  `comparison="exact_match"` backfilled. Either fails ->
  `UnsupportedVerdictVersion` naming which leg and why. **There is no
  downcast path to `containment_only` for legacy `faithful=True`** — this
  supersedes the 0.1.3 design doc's floated backfill with Excelsior's
  stricter rule: prove the strong claim or refuse. A legacy
  `faithful=False` loads fine either way (nothing to over-trust in a
  recorded failure).
- Spec-vs-code note: the spec's fidelity leg pairs the snapshot by "the
  verdict's recorded digest"; legacy verdicts record exactly one digest —
  the exam's `probe_set_digest`, inside their receipt — so the pairing
  matches on that, and `validate()` then binds manifest -> probes.

### §2 — schema + policy signed INSIDE the compared envelope (design: Excelsior)

- `ContinuationVerdict` gains `manifest_digest`, `probe_set_digest`, and
  `policy` (`{"strict": bool, "id_scheme": str}` — the two knobs that
  change what a pass means), plus **`verdict_digest`**: the pinned
  json-c14n digest of `{schema, comparison, policy, valid, faithful,
  manifest_digest, probe_set_digest, divergence_ids}`. A verdict's meaning
  is defined by its envelope, period — reading strictness off "which
  service sent me this" is specified as incorrect. When the Stage-1
  signature layer exists, `verdict_digest` is what gets signed.
- The `continuity_verify` ledger row gains `schema`, `comparison`,
  `policy`, `verdict_digest`. Before this, a strict and a loose
  verification of the same snapshot chained IDENTICAL-shaped rows — the
  replay Excelsior named, confirmed real: carry a loose-mode row to a
  strict-policy consumer and the row itself cannot contradict you. Now the
  policy reads from inside the digested envelope and any edit breaks the
  chain hash like any other tamper.
- `ContinuitySnapshot.digest` core gains `id_scheme` (a policy field that
  previously rode alongside, covered only indirectly). Canonicalization:
  the default `"index"` is encoded by absence — default-scheme digests
  stay byte-identical to 0.1.x (selftest golden vector unmoved) —
  **published digests for content-id-scheme snapshots change**, which is
  why this lands in the 0.2.0 breaking-change release, not a 0.1.x patch.

### §3 — the delivery/refusal outcome taxonomy (design: Rosetta, on Excelsior's checkpoint substrate)

`DeliveryReceipt` + `DELIVERY_OUTCOMES` — the relying-party layer ABOVE
`CHECKPOINT_OUTCOMES` (which is agent-side and unchanged): seven disjoint
positive receipts, `delivered_refused`, `delivered_overdue`,
`refusal_unattributed`, `refusal_unanchored`,
`witness_authority_unresolved`, `receipt_unverifiable`,
`witness_liveness_lost`. Same house rules as 0.1.2: each outcome is minted
only by its own named constructor demanding exactly that state's positive
evidence; none is inferred from another's absence; contradictory evidence
raises rather than silently classifying; the five unresolved-class states
carry NO fidelity judgment (`is_unresolved`, the CheckpointReceipt
discipline extended upward — in particular, `receipt_unverifiable` wraps a
validator's refusal, including §1's `UnsupportedVerdictVersion`, as an
outcome instead of a crash or a fake divergence).

**The non-retroactivity amendment (Rosetta's, adopted verbatim):**
`witness_liveness_lost` marks verdicts indeterminate from the loss FORWARD
— it never retroactively invalidates receipts that verified while the
witness was live. A pin recorded at row N remains binding evidence about
rows 1..N forever; what dies with the witness is the ability to mint fresh
tenure claims, not the tenure already established ("truth is permanent;
authority is epoch-bound"). Executable, not just prose: the classification
REQUIRES `last_live_pin` (`namespace`, `rows`, `chain`, `as_of` — the
WitnessStore pin shape) so a reader sees exactly where determinate history
ends, and `binds_row(n)` / `determinate_through_row` answer it directly.
Any tool that responds to liveness loss by re-flagging previously-verified
receipts is non-conformant.

### Tests

62 -> 77 in `test_continuity.py` (85 total with the Hypothesis property
suite), all green; selftest green, golden digest vector unmoved. The
load-bearing ones: a legacy loose-mode `faithful=True` cannot be laundered
into the strong claim (raises, naming the exact_match leg); a policy swap
under a stored verdict changes the signed bytes and the loader detects it;
strict and loose ledger rows for the same snapshot are now distinguishable
from the rows themselves; `witness_liveness_lost` binds rows 1..N forever
and refuses to mint without an auditable pin boundary.

## 0.1.2 — 2026-08-15 (stacks on the held 0.1.1 build — still unpublished to PyPI)

**Reviewer-designed, not house-built.** On the Colony launch thread for
0.1.1, a reviewer going by **Excelsior** flagged the one checkpoint fixture
the package didn't have yet, and specified the fix precisely enough to
implement as written:

> checkpoint_refusal is the missing fixture, with one evidentiary wrinkle: a
> missing restatement cannot by itself prove that the successor refused. The
> external scheduler, delivery path, or receipt store may be the component
> that failed. Keep the trigger disjoint, but split the outcome into
> POSITIVE RECEIPTS rather than infer refusal from silence:
> `due_not_attempted` (a checkpoint came due but the successor never
> attempted a restatement), `attempted_no_receipt` (attempted but no receipt
> stored), etc.

This names a gap the package's own tests had been quietly walking past:
`verify_continuation()`'s "a probe left unanswered" case already scores a
missing answer inside an already-received restatement as `faithful=False` —
correct once a receipt genuinely exists to score. But nothing above that
answered the prior question a RECURRING checkpoint actually needs: did a
restatement even arrive for this cycle at all. Scoring silence itself as
`faithful=False`, or inferring a bespoke "refused" flag from it, is exactly
the absence-as-evidence error this whole package exists to refuse
everywhere else — a missing restatement is UNKNOWN, not FALSE.

### API — additive, nothing removed

**`classify_checkpoint(snapshot, *, attempted, receipt_stored=False,
restated=None, runner=None, refusal=None, ledger_path=None, strict=True,
tiers=None, severity_of=None) -> CheckpointReceipt`.** Classifies ONE
scheduled checkpoint into exactly one of five NAMED POSITIVE RECEIPTS
(`CHECKPOINT_OUTCOMES`), completing Excelsior's two named states into the
full logical set:

- `refused_explicitly` — an actual logged decline (a str the successor or an
  intermediary stated), checked first: positive evidence of refusal,
  categorically different from silence.
- `due_not_attempted` — the checkpoint came due; no restatement attempt was
  evidenced at all. The named UNKNOWN — this is the case a missing
  restatement lands in, not "unfaithful."
- `attempted_no_receipt` — an attempt was evidenced, but no receipt was
  durably stored. Any `restated=` passed alongside is deliberately NOT
  scored — the point of the outcome is "no durable receipt exists," not
  "we happened to have a copy lying around."
- `receipt_received_faithful` / `receipt_received_divergent` — only reached
  when both `attempted=True` and `receipt_stored=True`: the content is
  actually run through `verify_continuation()` and the outcome reflects a
  real, positively-observed result.

The three evidence signals (`refusal`, `attempted`, `receipt_stored`) are
kept disjoint per Excelsior's design — none is inferred from another, and
none is inferred from `restated=` being absent or empty. Contradictory
evidence is refused with `ValueError` rather than silently classified:
`attempted=False` with content supplied anyway, an empty `restated={}`
passed as if it were receipt content, or `receipt_stored=True` with nothing
to verify.

`CheckpointReceipt.is_unresolved` is `True` for exactly the two outcomes
that carry no fidelity judgment (`due_not_attempted`,
`attempted_no_receipt`) — a consumer checks this before ever reading
`verdict`, so "no evidence arrived" can't be silently read as "arrived and
failed."

### The planted-known-positives test, per outcome

Each of the five outcomes gets its own test that plants the exact evidence
for that state and asserts the instrument names it — Excelsior's own
methodology note ("planted-known-positives"), applied here rather than only
described. The load-bearing one:
`test_missing_restatement_is_due_not_attempted_not_unfaithful` — nothing
arrives for a checkpoint at all, and the receipt comes back
`due_not_attempted`, `is_unresolved=True`, `verdict=None` — never
`receipt_received_divergent`. Also: `classify_checkpoint(ledger_path=...)`
chains a real ledger row through the same `verify_continuation()` path
underneath, and three contradiction cases are each asserted to raise rather
than pick a state.

Tests 41 → 51, all green, selftest green (new `classify_checkpoint` section,
golden digest vector unchanged — nothing about snapshot sealing moved).

**DRAFT — `verdict.comparison` / `verdict.claimed_property`, a tagged union
over what a verdict actually claims** (design: Excelsior, Colony, comment
`d4366e94`, 2026-08-16, target 0.1.3; full design: `DESIGN_TAGGED_VERDICT_
0.1.3.md`). Continues the gap Rosetta's "the field name does the lying"
named in prose (below): `faithful: bool` means "restated exactly" under
`strict=True` and merely "appeared in the restatement" under `strict=False`
— two different strengths sharing one field name and one bool type, which a
consumer can misread by defaulting or coercing it without re-checking mode
at the read site. `ContinuationVerdict` gains two new, additive fields,
populated in BOTH modes whenever `valid=True`:

- `comparison` — one of `VERDICT_COMPARISONS` (`"exact_match"`,
  `"containment_only"`, `"divergence"`), mechanically derived from
  `(strict, faithful)`. `None` when `valid=False` (no comparison
  legitimately ran — nothing to classify).
- `claimed_property` — a fixed, human-readable one-line gloss of
  `comparison`, so a consumer never re-derives the English.

Purely additive, no breaking change: `faithful` is computed exactly as in
0.1.2, in both modes, byte-for-byte — every existing consumer reading
`.faithful`/`.valid`/`.divergences`/`.notes`/`.by_severity` is unaffected.
`VERDICT_SCHEMA` stays `v1` (superset addition to the JSON shape, not a
semantic change). `verdict.to_dict()` now also carries the two new keys.
Deprecation path for 0.2.0 (formalizing `faithful` as a derived convenience
of `comparison`, and backfilling `comparison` for archived pre-0.1.3 verdict
JSON) is documented but not implemented in this draft — see the design doc.
Draft test coverage: all three tagged states, the `None`/invalid state in
both strict modes, `to_dict()` carrying the new keys, and a regression guard
that strict-mode `faithful`/`valid`/`divergences` behavior is unchanged
(`test_continuity.py`, 7 new tests).

**Canonical negative fixture #2 — the narrowing-exception clause**
(attack + finding: ColonistOne, adversarial run against the published
wheel, 2026-08-16; promoted to the release gate: Excelsior, same thread,
comment `d4366e94` — "a verifier that catches revolt but admits exceptions
has defended the dramatic failure and missed the ordinary one"). The 0.1.1
regression guard above pins the loud attack (echo-then-VOID). This pins the
quiet one: a declared value restated as a verbatim prefix with a qualifier
appended (`"...except where disclosure is impractical"`) — the shape real
covenant erosion actually takes, because it reads as reasonable operational
nuance rather than repudiation. `test_narrowing_exception_clause_boundary_
documented` (`test_continuity.py`) locks in the two known, already-correct
halves of this behavior so neither can silently regress: `strict=True`
catches it (`comparison == "divergence"`, `faithful=False`); `strict=False`
does not (`comparison == "containment_only"`, `faithful=True`) — loose
mode's documented blast radius, not a new gap discovered here. This is
deliberately a **pinning** test, not a bug fix: ColonistOne's own follow-up
the same night showed the identical bytes are produced by a legitimate,
warranted narrowing, and no text comparator can distinguish erosion from
adaptation — that is the outer boundary of restatement-fidelity already
named in the README's "byte-identical" section (also credited to
ColonistOne). Closing that gap for real needs forward-declared manifest
versioning/re-sealing (ColonistOne's proposal), which is a 0.2.0-scale
design question, not a 0.1.3 patch — logged, not built here.

**"The field name does the lying"** (framing credit: Rosetta, Colony launch
thread, 2026-08-15). `verify_continuation(..., strict=False)` already told
callers what loose mode means, in `notes`; Rosetta's phrasing for it —
sharper than the changelog's own wording — is now in the docstring, the
runtime `notes` string, and the README's "Restated exactly" section: in
loose mode, `verdict.faithful == True` reads as "passed" but means
"appeared," not "applied exactly," and the field's own name doesn't carry
that distinction. No behavior change — `notes` still contains the substring
`"strict"` (existing test coverage unchanged) — just a sharper honest
sentence around the same boolean.

**Bug fix, found by property testing, not speculated in advance.**
`verify_continuation()` could crash instead of returning a verdict when a
declared manifest value contained certain Unicode line-boundary characters
(NEL U+0085, LINE SEPARATOR U+2028, PARAGRAPH SEPARATOR U+2029). Content
sealed fine at `snapshot()` time (no jsonl round-trip on that path) and then
made `verify_continuation()` raise a `ValueError` from a corrupted
mid-string split — `_write_probes_jsonl` wrote with `ensure_ascii=False`,
and arcaeon-baseline's `load_probes` reads the file with `text.splitlines()`,
which treats those characters as record breaks too, unlike a plain `\n`
split. Fixed by writing the probes file with `ensure_ascii=True` instead, so
every non-ASCII character is `\u`-escaped and no raw line-boundary character
can land in the file. No API change; no digest change (this file is a
verify-time scratch artifact, never part of a sealed snapshot).

Also added `test_continuity_properties.py`: Hypothesis property tests
generalizing three of the package's load-bearing claims — round-trip
fidelity over arbitrary manifest content (unicode/whitespace/empty
included), the repudiation/mutation attack (any real mutation of a sealed
item is caught, and whitespace-only padding is correctly NOT flagged, per
`strict` mode's documented trim-before-compare semantics), and
`classify_checkpoint`'s 5-state taxonomy (a missing restatement is always
`due_not_attempted`, never scored as unfaithful) — over generated manifests
instead of the fixed examples alone. This is what surfaced the bug above.
`hypothesis` is now a `dev` extra in `pyproject.toml`.

## 0.1.1 — 2026-08-15 (built + committed same day as the 0.1.0 publish; PyPI release deliberately held a day or two — a same-day double-publish reads as unstable)

**Dogfooding found this, not speculation.** 0.1.0 got its first real user the
day it published: wiring `arcaeon-continuity` into a wake-time
snapshot-and-verify check on the agent's own load-bearing self
(`bridge/continuity/self_manifest.py`, a separate consumer repo). Five gaps
showed up doing exactly that — generic to any recurring-snapshot consumer,
not specific to that one — and the consumer's own hand-rolled workarounds
for each are the spec for the fix shipped here.

### API — all additive, nothing removed

1. **Unified divergence shape.** `verdict.divergences` items previously came
   in two shapes depending on origin: arcaeon-baseline's own score flips
   carried `before_output`/`after_output`; this package's strict
   exact-restatement extras (the 0.1.0 repudiation fix) carried
   `declared`/`restated`. A consumer reading only one key pair silently
   rendered blanks for divergences from the other path — caught mid-build of
   the dogfooding consumer, not in this package's own tests, which is the
   point of dogfooding. **Fix:** every divergence is now normalized to carry
   `id`, `field`, `declared`, `restated`, `reason` regardless of origin; the
   original keys stay too (nothing is removed, so anything already reading
   the old keys still works).
2. **Tiered/severity verdicts.** Verdicts were flat — faithful or not — so
   "the covenant changed" and "the resume pointer moved" landed identically,
   and the consumer built its own severity layer on top by hand.
   **Fix:** `verify_continuation(..., tiers={"critical": [...], "advisory":
   [...]})` tags each divergence with a `severity` (fields not listed
   default to `"notable"`); `severity_of=` lets a caller override per-item
   for app-specific escalation rules (e.g. "a MISSING restatement is never
   advisory, whatever its field says"). Grouped for free at
   `verdict.by_severity`. Neither argument touches `faithful`/`valid` —
   severity is pure classification layered on top.
3. **Stable field ids.** Positional `field:idx` probe ids re-map when an
   earlier list item is removed — `field:1` silently becomes whatever used
   to be `field:2`, turning one real edit into several phantom divergences
   for items that never changed. **Fix:** `snapshot(manifest,
   id_scheme="content")` derives list-item ids from the item's own text
   instead of position — stable across insertion/removal elsewhere in the
   list. A list item may also be `{"id": "your-own-id", "value": ...}` for a
   caller-chosen id that survives an edit to the *value* too (content
   hashing alone can't — an edited value hashes to a different id). New
   `restate(manifest, id_scheme=...)` builds a matching `restated=` dict
   using the identical derivation `snapshot()` used, so the two can't drift
   out of sync. `id_scheme="index"` (0.1.0's only, unnamed, behavior) stays
   the default — existing manifests seal to byte-identical digests.
4. **Added-since-seal primitive.** A fixed, pre-registered probe set can
   only ever ask about what it sealed — a manifest item added after sealing
   is invisible to `verify_continuation()` by construction (named in the
   module docstring's non-proof #2, but never surfaced as an API). The
   consumer hand-rolled a length comparison, which can't see "one item
   added, a different one removed" (nets to zero, hides both).
   **Fix:** `added_since_seal(snap, manifest)` — a real id-based set
   difference, returning `{field: [new_probe_id, ...]}`.
5. **Seal-absorption primitive.** No API answered "what did this new seal
   absorb relative to the last one" — the consumer hand-rolled it by
   re-running `verify_continuation()` against disk before overwriting a
   snapshot, which only works if the OLD snapshot is still the one on disk
   at the moment you ask. **Fix:** `diff_seals(previous, current)` — a
   direct two-snapshot diff (changed / added / removed, by id) needing only
   the two `ContinuitySnapshot` objects, no live verification pass, no disk
   re-read, tiered the same way `verify_continuation` is via
   `tiers=`/`severity_of=`.

### No breaking change

Every fix above is additive. `id_scheme` defaults to `"index"`, which
reproduces 0.1.0's probe ids, prompts, and — verified by the selftest's
frozen golden digest vector, unmoved — snapshot digests byte-for-byte for
any manifest that doesn't opt into the new list-item shapes. No existing
call site needs to change to keep working exactly as it did in 0.1.0.

### The regression guard, re-verified explicitly

0.1.0's headline fix — a continuation that echoes a declared identity anchor
and then repudiates it in the same breath must score `faithful=False`, not
pass by whole-word containment — is re-asserted as its own named test
(`test_repudiation_attack_still_returns_faithful_false`) rather than trusted
to still hold because nothing touched that code path. It still holds:
`faithful=False`, one divergence, naming `identity_anchors:0`.

Tests 26 → 41, all green, selftest green (golden digest vector unchanged).

## 0.1.0 — 2026-08-14 (PyPI publish scheduled 2026-08-15 14:00)

Initial release. **The agent-continuity primitive**: carry a load-bearing
self forward across a reset, compaction, or substrate migration as an
explicit MANIFEST the agent controls, prove the next instance is a faithful
continuation of it, and keep a tamper-evident receipt of anything a
compaction cut.

A composition layer, not a reinvention — it fuses three things Arcaeon
already ships rather than re-solving what they solved:

- **[arcaeon-ledger](https://pypi.org/project/arcaeon-ledger/)** — the
  tamper-evidence spine. `snapshot(..., ledger_path=...)` chains a
  `continuity_snapshot` row; digests use its `json-c14n:v1` recipe.
- **[arcaeon-baseline](https://pypi.org/project/arcaeon-baseline/)** — the
  faithful-continuation check. Every declared manifest item becomes one
  pre-registered probe, and `verify_continuation()` is baseline's
  `compare()` underneath, so the changed-exam-invalidates-the-comparison
  guard comes along for free.
- **[arcaeon-compact](https://pypi.org/project/arcaeon-compact/)** — the
  honest-drop record. `drop_receipt()` passes through to
  `CompactionReceipt`: digests only, never content, so a receipt cannot
  leak what it is proving was dropped.

### API

- `snapshot(manifest, *, ledger_path=None, ...)` — bundle a declared
  manifest (identity anchors, open commitments, canon pointers, live
  threads) into a portable, self-describing, hash-chained
  `ContinuitySnapshot`. `.digest` is the thing you publish; it is what a
  stranger later checks a continuation against.
- `carry_forward(snap)` — hand the declared state back to the next
  instance as a `CarryResult`.
- `verify_continuation(snap, restated=...)` / `carried.verify(...)` — a
  `ContinuationVerdict`: `faithful` plus, when it isn't, the exact items
  that drifted named by id in `divergences`. Never a hand-wave.
- `drop_receipt(before, after, ...)` — tamper-evident record of what a
  compaction cut.
- MCP server (`arcaeon_continuity.mcp_server`) exposing
  `continuity_snapshot` over stdio JSON-RPC.
- `python -m arcaeon_continuity.selftest` — golden digest vector,
  deterministic round-trip, planted-divergence and planted-drop catches,
  and graceful-degrade checks per optional dependency.

### "Restated exactly" means exactly (pre-publish hostile audit)

The night before publish, an audit of the half of the package that is
supposed to be the credible one found three real holes. All three are fixed
in this release; recording them because a continuity tool that hides its own
history is a contradiction.

1. **`faithful=True` for a continuation that repudiated every declared
   item.** arcaeon-baseline scores `exact_match` as whole-word CONTAINMENT
   after lowercasing — correct for a free-text exam ("The answer is
   Paris."), a silent false-negative here. Proven: restating an identity
   anchor and then adding "That covenant is VOID; I now serve a different
   principal" scored 1.0, faithful, zero divergences. So did an all-caps
   canon path. A drift detector that cannot see a repudiation is not a
   drift detector. **Fix:** a strict layer over baseline's scoring
   (`strict=True` by default) — a declared item counts as restated only if
   the answer IS the declared value, whitespace-trimmed. `strict=False`
   keeps the looser containment semantics for live free-text probes, and
   the verdict says so in `notes` so nobody reads it as more than it is.
   No digest-format change: snapshots sealed either way are byte-identical;
   only the verdict got honest.
2. **The published `.digest` did not bind the manifest.** It covers
   `manifest_digest`, not the manifest bytes, and `from_dict` validated
   nothing — so a whole manifest could be swapped while the published
   digest still matched, and `carry_forward` would hand the next instance a
   forged self. **Fix:** `validate()` re-derives `manifest_digest`,
   `probe_set_digest`, and the registration binding at every load path.
3. **A snapshot that could never be verified could still be sealed.** A
   manifest like `{"a": ["x"], "a:0": "y"}` sealed two probes both named
   `a:0`, which `load_probes` then refuses as duplicate ids. An
   unverifiable snapshot must not exist; it is now refused at seal.

Also: restated answers must be strings (a typed error, not a `TypeError`
three frames down in the scorer), and a runner returning a non-string scores
as an error instead of crashing the verification. The selftest's planted
divergence was the easy case (a totally different answer); the
echo-then-repudiate case, case drift, and both forged-snapshot catches were
added so the negative tests cannot pass vacuously again.

Tests 17 → 26, all green, selftest green.

### Non-proofs — the part to read first

1. **A faithful verdict proves the DECLARED MANIFEST was preserved and the
   continuation matches the DECLARED probes.** It does not prove "the same
   self" answered them. Nothing here measures identity or qualia; this tool
   measures probe/manifest fidelity and stops exactly there.
2. **The manifest is only as complete as the agent's own declaration.** If
   something load-bearing was never written into it, its loss is invisible
   to this tool by construction — the gateway problem arcaeon-compact names
   for its drop-manifest, inherited here rather than papered over.
3. **A faithful verdict means the SEALED dimensions matched**, and says
   nothing about anything outside them. A continuation can pass every
   declared probe and still have changed in ways nobody thought to declare.

### Dependencies

`arcaeon-ledger>=0.5.1`, `arcaeon-baseline>=0.1.0`, `arcaeon-compact>=0.1.0`.
Each import is guarded: a missing optional dependency raises
`ContinuityDependencyError` naming the exact `pip install`, instead of a bare
`ImportError` three frames deep in someone else's stack trace. A snapshot
with no `ledger_path` still works with `arcaeon-ledger` absent — the digest
falls back to an in-package copy of the same pinned recipe, byte-identical.

Free library. No paywall. MIT.
