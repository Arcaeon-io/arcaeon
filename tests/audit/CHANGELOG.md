# Changelog — arcaeon-audit

## v0.1.8 — 2026-09-01 (sell-code audit: six findings, none of them a verdict on a clean log)

A pre-sale audit of the published 0.1.7. Every item was reproduced against
the released code before it was touched, and every fix ships with the test
that was red. No verdict or exit code changes for a well-formed log with a
well-formed witness; what changed is what the bundle SAYS and what a caller
can smuggle into it.

**Fixed: the re-verify `curl` command was a shell-injection vector.** The
namespace (chosen by the audited party) and the pin's rows/chain (read from a
file) were interpolated raw into a single-quoted shell command that the
bundle asks a regulator to paste. A namespace of `acme'; rm -rf ~; echo '`
produced exactly that command, in both `integrity.json`'s
`how_to_reverify.step_2` and `ARTICLE_12_SUMMARY.md`; a namespace containing
`&` or `#` silently rewrote the query. All three values are now
percent-encoded (`quote(..., safe="")`), so the string can hold nothing a
POSIX single-quoted argument or a URL query can misread.

**Fixed: a `witness_descriptor()` could write ANY string into `kind` and
`independence`.** Both were copied out of the auditee's dict verbatim.
`independence: "CERTIFIED_BY_REGULATOR"` shipped as-is into the field a PASS
is weighed on; `kind: "none"` made the summary drop its independence paragraph
entirely (the summary skips kind `none` because that means no witness). A
descriptor may now declare only the documented vocabulary (`remote_url` /
`opentimestamps`; `self_asserted` / `externally_verifiable`); anything else is
treated as if it had said nothing — the conservative default, never a new label.

**Fixed: `truncation_ok: false` beside a verdict that says "not tampering".**
`truncation_ok` was `wv.verdict == "consistent"`, so `witness_broken`,
`local_broken`, and any verdict this version does not know all produced
`false` — an accusation in a field — under `WITNESS_CHECK_FAILED` /
`UNRECOGNIZED_WITNESS_VERDICT`, whose prose says the comparison never ran. It
is now tri-state like `chain_ok`: `true` on consistent, `false` on truncated /
rewritten, `null` when the ledger refused to compare.

**Fixed: the summary printed a stand-in instead of the witness's detail.**
`WitnessVerdict` is truthy only on `consistent`, so every `wv.detail if wv
else ...` in the prose took the `else`: `TRUNCATION_DETECTED` said "the witness
reported truncation" instead of "log has 2 rows but the witness recorded 4: 2
witnessed row(s) are missing", `WITNESS_CHECK_FAILED` said "witness
unavailable" for a witness that answered, and the unrecognised-verdict label
read `UNRECOGNIZED_WITNESS_VERDICT:none` instead of naming the verdict. The
numbers were in `integrity.json` the whole time; the page a regulator reads
did not have them. `is not None` throughout.

**Fixed: one bundle, two row counts.** The manifest's reader decoded strictly
and the ledger's `verify_file` decodes with `errors="replace"`, so a row with
one corrupted byte was `unreadable` to `manifest.json` (`record_count: 2`) and
a parsed, chain-broken row to `integrity.json` (`rows: 3`). The manifest
reader now decodes the way the verifier does; the two files count the same
lines. The same reader also catches `RecursionError` (what `json.loads`
actually raises on a pathologically nested line, not `ValueError`). Note that
`arcaeon-ledger`'s own `verify_file` still raises on that line, so
`export_bundle` as a whole does not yet survive it — that half lives in the
ledger and is out of this package's hands.

**Fixed: `record(authority=..., chain=...)` silently dropped the caller's
data.** The reserved-key rule exists because "a dropped field is its own quiet
surprise", and it covered `ts` / `system_id` but not the two keys the ledger
stamps one layer down: a caller's `authority=` was replaced by the block
`record()` builds and `chain=` was popped, both without a word. Both are now
refused with the same `ValueError` and the same "pass it as `<key>_value`"
advice.

## v0.1.7 — 2026-08-28 (two verdicts were right and the sentence beside them was false)

An external audit of the published package. No verdict, exit code, or key
changed — this release is entirely about bundles whose PROSE contradicted their
own `integrity.json`. A regulator reads the sentence, and a sentence that
launders a skipped check into an absent one is the same defect as a check that
reports clean without having run.

**Fixed: a HALF-CONFIGURED witness was described as no witness at all.**
`export --witness w.jsonl` with `--namespace` forgotten (or the reverse) runs no
truncation cross-check at all, exits 0, and printed *"TRUNCATION NOT CHECKED —
no external witness was consulted"* — over a run whose own `witness` block in the
same `integrity.json` records `kind: local_file` and the store's path. One
artefact, two contradictory statements about whether a witness existed. This is
0.1.5's C9 defect (a mistyped namespace silently disabling the check at zero
visible cost, chosen by the party being audited) one argument over: C9 caught the
mistyped namespace, and the OMITTED namespace walked straight past it. The
summary now says the check was SKIPPED and names which argument is missing.
Also removes the `no_pin` branch this replaced, which had been unreachable since
C9 routed `no_record` to `WITNESS_CHECK_FAILED`.

**NOT changed, deliberately, and flagged for a decision:** that case still exits
**0**. By the CLI's own stated contract (`2` = the check could not complete) a
configured-but-unrunnable witness check arguably belongs at exit 2, exactly where
the mistyped-namespace case already sits. Changing it would turn a currently
green CI job red for anyone who passes `--witness` without `--namespace`, so it
is named here rather than taken silently.

**Fixed: `UNVERIFIED_SCOPE` told one story about a scope that has several.**
arcaeon-ledger 0.6.0 added `bounded_declared_break`, whose `prechain` is 0, and
this rendered *"the chain could not speak for **0** of them: they carry no chain
links"* — a count that contradicts its own verdict, a cause the reader does not
have, and then advice ("chain the log going forward") for a condition they are
not in. Both the bundle summary and `arcaeon-audit verify` now read the ledger's
scope fields and name the actual bound: unchained rows, declared breaks, or an
unrecognised scope reported as unrecognised. The `UNVERIFIED_SCOPE` verdict and
its exit 2 are unchanged.

**Audited and found sound** (recorded so the next audit can skip them): the
three-valued contract is consumed correctly — `ok=True` is only ever reached with
`verified_scope == "full"`, every bounded scope falls through to
`UNVERIFIED_SCOPE`/exit 2, and `EMPTY_LOG` requires `scope == "empty"` AND
`rows == 0`, so 0.6.0's new scope strings are handled fail-safe by construction
rather than by luck. No non-ASCII or control characters in any pattern or
matcher. No dead code. README examples run and produce what they document.

## v0.1.6 — 2026-08-28 (instrument defects: the check gets to confess its own blind spots)

**New: `--instrument-notes <path>` on `export`, `instrument_notes=` on
`export_bundle()` / `AuditLog.export_bundle()`.** An author-written statement of
THIS check's known false-positive modes, known false-negative modes, and what was
NOT exercised, carried into the bundle: byte-for-byte as `INSTRUMENT_NOTES.md`,
as a newline-preserving string under `integrity.json`'s `instrument_notes`,
pinned by `instrument_notes_sha256`, and reproduced under an `## Instrument`
heading in `ARTICLE_12_SUMMARY.md`. The README documents the convention and ships
a copy-pasteable template.

**Why.** Audit tooling reports verdicts and leaves the limitations in a chat log,
a ticket, or somebody's head — anywhere except the artefact the auditor actually
reads, which means the artefact overstates itself by omission. A checker that
names its own blind spots is more trustworthy than one that does not, because the
second one's silence is indistinguishable from having none, and nobody has none.
This is the cheap half of that: a slot that travels with the bundle.

**Verbatim is the whole feature.** The notes are read as bytes and decoded strict
UTF-8 — not `read_text()`, which would have silently folded CRLF to LF on Windows
— and written back as bytes. Nothing is reflowed, re-wrapped, stripped, or
normalised. A disclosure edited by the tool reporting on it is no longer the
author's disclosure. Tested on exact bytes and sha256, never on `in`: a
containment assertion passes on a reflowed copy, which is exactly the regression
worth catching.

**Contents are never validated, on purpose.** No schema, no required heading, no
lint. The value is the slot existing, not this package having an opinion about
what belongs in it — and a validator would only teach people to write whatever
passes it.

**Asked for and unreadable = abort, exit 2, nothing written.** A missing,
unreadable, or non-UTF-8 notes file kills the export before the output directory
is created. Emitting the bundle anyway would produce an artefact
indistinguishable from one whose author was never asked to disclose anything —
an absence laundered into a presence, in a regulator-facing document, at exit 0.
Exit **2** ("the check could not complete"), matching the existing contract:
nothing is wrong with the LOG, the operator asked for something this run cannot
honour. Its planted red (`test_instrument_notes.py::
test_missing_notes_file_never_produces_a_bundle`) was demonstrated failing
against a build with the abort removed — it exited 0 with a full bundle on disk
and an empty stderr — before being committed.

**Backwards compatible, verified by diff, not by assertion.** Without the flag:
no new key in `integrity.json`, no new file in the bundle, no warning on stderr,
no change to `ARTICLE_12_SUMMARY.md` (a nag on every export would only train
people to ignore it). The same log exported by 0.1.5 and 0.1.6 with no flag was
diffed file by file: `records.jsonl` byte-identical, and the other three
identical apart from the wall-clock timestamp and the version string. Suite
**52 → 62 passed**.


## v0.1.5 — 2026-08-24 (the dependency pin that excluded the fix it ships, plus five more from the same audit)

**C12 — the release-blocking finding, fixed last.** `pyproject.toml` pinned
`arcaeon-ledger>=0.5.8,<0.5.9` — the cap excluded 0.5.9, the release
containing the entire witness-integrity defense (pin chains, edited-pin
detection, the guards this package's own tri-state logic depends on). Every
fix below ran green in CI against a working tree no customer's `pip install`
ever produces; against the actual minimum declared dependency (0.5.8),
`WITNESS_CHECK_FAILED` was dead code and a forged, truncated witness scored
`PASS`. Fixed: pin changed to `>=0.5.9`, published alongside this release —
both ship together or neither works.

**Also fixed this pass, all from the 2026-08-23 four-pass adversarial audit
run before comping outside critics access to Arcaeon Witness:**
- **C4** — `independence: externally_verifiable` was settable by omission
  and defaulted OPEN: a duck-typed `.url` attribute on the store was enough
  to earn "externally verifiable" status. Reordered the `isinstance` check
  ahead of the descriptor branch; default is now `undeclared`, and
  `independence`/`note` are never read off the store's own self-description.
- **C5** — the bundle called a fabricated prepend "not evidence of
  alteration" while this package's own docstring says the opposite: it is
  undecidable. Now requires `lenient.chained > 0` before that claim, and
  states the undecidability verbatim rather than asserting a false negative.
- **C6** — `how_to_reverify` told a skeptical reader to trust the audited
  party's own re-run. Wired in the public `GET /api/verify` URL — an
  independent, out-of-band check — the cheapest, highest-value item on the
  list.
- **C9** — a typo'd namespace silently disabled the truncation check
  entirely; no error, no warning, just a check that never ran.
- **C10** — the PyPI `Source` link 404'd (a stale repo path).

Each carries its own planted red, per the lesson C1 (below) already
taught this package: a fix without a demonstrated-failing test first is a
record of a fix, not a fix.

### The tri-state OVERSHOOT: a tampered log exported as "no records have been written yet"

Found 2026-08-23 by a four-pass adversarial audit run BEFORE comping witness access to outside expert critics. The gate existed to answer "is this good enough to hand to people who will attack it"; the answer was no, and this was the worst of it.

**The defect.** The 2026-08-23 tri-state fix (below, in this same Unreleased block's lineage) cured a real false-FAIL — a day-one customer's empty log was accused of tampering — and **overshot into a false-PASS, which is strictly worse.** `verify_file` returns `ok=None` for TWO different reasons: an empty file (`verified_scope == "empty"`) and unchained rows skipped (`"bounded_prechain_skipped"`). `export_bundle` never read `verified_scope`, so it collapsed both into `EMPTY_LOG` — and because that branch ran FIRST, it also **masked a positive witness detection**.

Reproduced: strip the `chain` key from every row, alter one witnessed row, delete three more. The witness correctly returns `truncated`. The regulator-facing `ARTICLE_12_SUMMARY.md` read *"EMPTY_LOG — no records have been written yet. There is nothing to verify and nothing to accuse"* over a bundle containing seven records, three of them missing and one altered. Exit code 0.

It also hit honest users: the documented adoption path leaves prechain rows, so **a real adopter's real log exported as "no records have been written yet."**

- **A positive external detection now outranks any chain-scope verdict.** The witness branches (`truncated` / `rewritten` / `witness_broken` / `local_broken`) are evaluated BEFORE the `ok is None` branches. What the witness saw is evidence; what our chain could not scan is not, and a scope verdict must never overwrite a detection.
- **`EMPTY_LOG` now means EMPTY** — `verified_scope == "empty"` AND `rows == 0`. Nothing else.
- **New verdict `UNVERIFIED_SCOPE`** for rows that exist but carry no chain links: not a pass, not an accusation, an unanswered question, with prose that says so and names the row counts. Maps to **exit 2** (`export`), because an unanswered question must never gate CI green.
- **Accusation prose no longer asserts a clean chain it did not verify.** `TRUNCATION_DETECTED` and `WITNESS_CHECK_FAILED` previously opened "the chain itself is intact" — false on exactly the path this fix enables. They now state the real chain state, including "the chain could not speak for these rows."
- **`cli.py verify` no longer collapses the tri-state.** `if r.ok:` sent `ok=None` down the FAIL branch, so an empty log printed *"integrity broken at None — altered, truncated, or reordered"* and exited 1, while `export` on the SAME file exited 0. Two subcommands, two contradictory verdicts, one file. `verify` now matches export's contract: EMPTY → exit 0, UNVERIFIED → exit 2, FAIL → exit 1.
- **Three planted reds** (`test_witness_truncation.py`), each failing before the fix and passing after: the tampered-unchained log must not report EMPTY_LOG and must keep the witness detection; the honest adopter's log must not be called empty; and a genuinely empty log must STILL report EMPTY_LOG, so the original false-FAIL fix cannot silently regress. Suite **26 → 29 passed**.

The lesson worth keeping: a fix that moves an error to the opposite sign is not a fix. The original correction shipped without a planted red for the branch it created, and that is the only reason this survived a day.

### Hypothesis property-test pass (no bug found in this package)

Companion pass to arcaeon-ledger's Unreleased entry: arcaeon-ledger's `verify_file`/`__iter__`/`chain_at` had a real "sealed but unverifiable" bug (U+0085/U+2028/U+2029 in row content, written raw under `ensure_ascii=False`, fractured by a read-side `str.splitlines()`) — fixed there. This package's own `_read_rows` was checked and was **never vulnerable**: it has always split on `raw.split(b"\n")` at the byte level, not `str.splitlines()`. No code change was needed in `arcaeon_audit/__init__.py`.

- **New: `test_hypothesis_audit.py`**, a `hypothesis`-driven property suite covering this package's own verify surface (not re-testing ledger primitives, which have their own suite): (1) any sequence of honest `.record()` calls exports clean — `chain_ok=True`, zero unreadable lines, verdict never `FAIL`; (2) any single row mutated in an exported `records.jsonl` fails the bundle — `chain_ok=False`, verdict `FAIL`, reproducible via both `verify_file()` and a full `export_bundle()` re-run; (3) the U+2028-class characters specifically survive `record → export → re-verify` end to end (both in combination and pinned one at a time), locking in that the composed pipeline stays correct now that the ledger dependency is fixed; (4) witness-based truncation verdicts (`PASS` vs. `TRUNCATION_DETECTED`) match the pin-vs-kept-row-count relationship across randomized `n`/`keep` pairs.
- **Environment fix, not a code fix:** the installed `arcaeon-ledger` dependency (used by this package and every other Arcaeon package on this machine) was a **stale, non-editable copy** in site-packages — a `pip install file:///...` without `-e`, so fixes landing in the `arcaeon-ledger` source repo were silently not reaching any dependent. Reinstalled as `pip install -e arcaeon-ledger --no-deps` so this package (and `arcaeon-baseline`/`arcaeon-compact`/`arcaeon-continuity`) actually run against current source going forward. Purely local dev-environment hygiene — no version bump, no PyPI publish, nothing pushed.
- Full suite: **21 → 26 passed** (5 new property tests; no regressions).

## v0.1.4 — 2026-08-15 (surface the witness's NATURE so a regulator can judge independence)

The 2nd-pass scrutiny audit (HIGH-2) left one honesty debt as an additive follow-up: a bundle stamped `PASS` "verified against a witness," but nothing in it told a regulator *what* the witness was — an independent remote notary, or just another local file the same party controls (which proves nothing about independence). A self-controlled witness is forgeable (truncate the log, re-pin the local file → forged PASS), and the bundle was silent on the difference. This release makes the independence question **visible**. (Carries forward tonight's PASS-completeness text fix, below.)

- **`integrity.json`'s `witness` block now names the witness's NATURE.** It carries `kind` (`local_file` / `remote_url` / `opentimestamps` / `none`), an `identifier` (the local path or the endpoint/anchor — never a secret), and an explicit **`independence`** label (`self_asserted` / `externally_verifiable` / `none`) with an honest `note`. The reference `WitnessStore` is a local JSONL — same control domain as the log — so it is labelled `independence: self_asserted` with the note: *"This witness is a local file … so it is NOT independent … A PASS backed by it is SELF-ASSERTED, not externally verified."* The verification fields (`verdict`, `witness_rows`, `local_rows`, `pin`, …) ride alongside the nature fields in the same block. This does **not** change any verdict — it lets a regulator SEE the independence question the verdict can't answer for them. The honesty contract is the whole product: label a self-controlled witness as such, never dress it up as independent.
- **No witness → `witness: {kind: "none", independence: "none", …}`** (was `null`). The block is always present now.
- **A witness can self-declare** via an optional `witness_descriptor()` method returning `{kind, identifier, independence, note}` — how a hosted-notary or OpenTimestamps client advertises `externally_verifiable` independence. Anything that isn't the reference local store and doesn't self-declare is treated conservatively (independence not claimed).
- **Schema-additive, back-compatible.** `integrity.json` gains `bundle_schema: 2` and the nature keys; old readers ignore them. New `witness_nature_of(integrity)` reads bundles both ways and reports **`kind: "unknown"`** for pre-v2 bundles (witness block that predates the nature fields, or absent, or `null`) rather than guessing an independence — never raises.
- **`ARTICLE_12_SUMMARY.md`** gains a "Witness independence" line and mapping bullet; the **CLI** `export` prints `Witness: <kind> (independence=<independence>)`.
- Four tests added to `test_witness_truncation.py` (local-file→self_asserted+note, no-witness→kind none, self-declared remote→externally_verifiable, old-bundle→unknown). Full suite: **21 passed**.

### 2026-08-15 — honesty fix (PASS certificate scoped to what it can prove)

Adversarial 2nd-pass scrutiny (`projects/online_business/SCRUTINY_AUDIT_2026-08-15.md`) found the `PASS` verdict overclaimed in two ways; both are now corrected in the regulator-facing bundle text and the README. No schema/format change — `integrity.json` keys and all five verdicts are unchanged; the 17-test suite still passes.

- **PASS no longer claims a completeness it can't prove.** The witness pins the head only on a cadence, so records written *after the last pin* can be dropped and the export still reads PASS. The old summary asserted the inverse — "no records were dropped after the witnessed point" — when that region is exactly the unprotected one (reproduced: pin@4, grow to 10, truncate to 4 → PASS with 6 real records gone). The PASS line now says the witnessed **prefix** is complete ("no records dropped AT OR BEFORE the witnessed point"), warns that anything past the witnessed head can be dropped undetectably, and tells you to pin close to export. README PASS bullet rescoped to "completeness only through the last pin."
- **PASS now states its independence assumption.** A witness only proves anything if it is controlled independently of whoever can write the log; the reference `WitnessStore` is a local file and the README example pins right next to the log (an attacker who truncates can also re-pin → forged PASS). The PASS text and README now say the guarantee assumes an independently-controlled witness. (Surfacing *what* the witness was inside `integrity.json` is left as an additive follow-up.)
- **Flagged, not fixed:** the installed/published PyPI `0.1.0` still crashes on import (`from ledger import` — pre-scar-#83); publish 0.1.3 or yank 0.1.0. Timestamps are notarized as-is with no monotonicity check.

## v0.1.3 — 2026-08-14 (close the truncation gap — with a witness)

0.1.2 called out a scoped gap and left it: an export still stamped PASS on a *truncated* log, because a hash chain provably cannot see truncation (delete the last N rows and the surviving prefix still chains clean). A "regulator-ready" bundle that clean-passes a log missing its most recent records is the exact overclaim this product exists to prevent. 0.1.3 closes it — with an external witness, and honestly says so when there isn't one.

- **`export_bundle()` gains an optional witness cross-reference.** Pass `witness=` (a `WitnessStore`, a path to one, or any object with `.latest(namespace)` — e.g. a hosted-witness client) and `witness_namespace=`. The export cross-checks the *exported* `records.jsonl` against the witness's pinned head via arcaeon-ledger's `verify_against_witness`: a log with fewer rows than the witness saw is caught as truncation; a re-minted-but-internally-clean log is caught as a rewrite.
- **The bundle's verdict now distinguishes three things, reported separately in `integrity.json`:** `chain_ok` (no edit/reorder within the log), `truncation_checked` (was a witness actually consulted), and `truncation_ok` (did it pass). The single top-level `verdict` is one of `PASS`, `VERIFIED_MODULO_TRUNCATION`, `TRUNCATION_DETECTED`, `REWRITE_DETECTED`, or `FAIL`. **A bundle only says `PASS` when truncation was actually checked against a witness and passed.** With no witness it says `VERIFIED_MODULO_TRUNCATION` — chain intact, completeness *not* proven — never a clean pass. (`ok` is retained as an alias of `chain_ok` for back-compat.)
- **`witness.json` is added to the bundle** when a witness is consulted: the pin (`namespace, rows, chain, as_of`, and any extra fields the witness recorded such as an OTS anchor receipt — passed through verbatim) plus the truncation verdict and detail. A durable, self-contained cross-reference inside the bundle.
- **`ARTICLE_12_SUMMARY.md` no longer implies completeness it can't prove.** The Integrity line reflects the distinguished verdict; a new mapping bullet explains that truncation is the one failure a chain can't catch alone and how the witness closes it.
- **`AuditLog` can carry a witness** (`witness=`, `witness_namespace=` on construction), with `pin_to_witness()` to record the head on a cadence and `export_bundle()` picking the config up automatically.
- **CLI:** new `arcaeon-audit pin <log> <witness> <namespace>`; `export` gains `--witness`/`--namespace` and prints the distinguished verdict; `verify` now notes plainly that chain verification cannot detect truncation.
- Seven tests added (`test_witness_truncation.py`), each written failing against 0.1.2: truncated-with-witness → `TRUNCATION_DETECTED`; truncated-without-witness → chain still clean but verdict `VERIFIED_MODULO_TRUNCATION` (never PASS); untruncated-with-witness → `PASS`; witness-configured-but-no-pin → honest not-checked; rewrite → `REWRITE_DETECTED`.
- **Non-proof, downgraded (was "unchanged and deliberate" in 0.1.2):** truncation is now caught **when a witness is configured**. Without a witness, an export cannot detect truncation and says so — it reports `VERIFIED_MODULO_TRUNCATION`, not PASS. The witness's own limit still travels with the claim: it proves the log was not truncated *relative to what the witness saw, and only as recently as the last pin* — the max gap between pins is the real security parameter, and an attacker picks the gap.

## v0.1.2 — 2026-08-14 (export robustness — hostile audit)

The export exists to hand a regulator the evidence. Through 0.1.1 it crashed on precisely the logs that most need exporting: the damaged ones.

- **`export_bundle()` no longer crashes on a damaged log.** It read the file with `read_text(encoding="utf-8")` and ran a bare `json.loads` per line, so an unparseable line raised `JSONDecodeError`, a non-UTF8 byte raised `UnicodeDecodeError`, and a bare scalar line (`123`) raised `AttributeError` inside the summariser. The result: a log with any tampering that damaged a line produced **no bundle at all**, exactly when the export was needed as evidence. Unreadable lines are now counted, not fatal, and reported as `unreadable_lines` in `integrity.json` and `manifest.json` and called out in `ARTICLE_12_SUMMARY.md`. An export never silently drops what it cannot read.
- **`records.jsonl` is now a byte-for-byte copy of the log.** It was a re-serialization (`json.dumps` of each parsed row, written with `write_text`, which on Windows also rewrote every LF to CRLF), while the docstring promised "the full hash-chained audit log (verbatim)". Now it is the source bytes.
- **`integrity.json` describes the file the bundle actually contains.** Verification ran against the *source* log path while the bundle shipped the re-serialized copy — a verdict about a file that was not in the folder. It now verifies `records.jsonl` itself, and pins exactly which bytes were checked with `records_sha256` plus `verified_file`. A regulator-facing artefact has to be self-contained and re-checkable from the folder alone; that is now literally true.
- **Also in `integrity.json`:** `breaks` (total, not just the first) from arcaeon-ledger 0.5.3.
- **Dependency floor raised to `arcaeon-ledger>=0.5.3`** — the release that fixes the chain reset on rows larger than 8 KB, which silently detached history in any audit log containing a large record (a captured page, a big tool output). That is a correctness floor for this package, not a preference.
- Ten regression tests added (`test_export_robustness.py`), each written failing first.
- **Known scoped gap, unchanged and deliberate:** an export still stamps PASS on a *truncated* log, because the bundle does not reference an external witness. A hash chain cannot see truncation on its own; closing it is a build item, tracked separately.

## v0.1.1 — 2026-08-14 (bugfix)
- **What:** 0.1.0 was uninstallable-as-published — stale import name; caught by our own
  verify-bundle build. `arcaeon_audit/__init__.py` imported `from ledger import ...` (the
  pre-0.2.1 arcaeon-ledger module name) instead of `from arcaeon_ledger import ...`, in both
  the module-level import and the `how_to_reverify` string embedded in exported bundles.
  A clean `pip install arcaeon-audit` + `import arcaeon_audit` failed on 0.1.0.
- **Fix:** both stale `ledger` references corrected to `arcaeon_ledger`. Dependency floor
  raised to `arcaeon-ledger>=0.5.1` (the version actually on PyPI; 0.1.0's `>=0.2.0` floor
  predated the `ledger` → `arcaeon_ledger` rename).
- **Verified:** clean venv, `pip install arcaeon-ledger==0.5.1` then editable install of the
  fixed package, `import arcaeon_audit` succeeds, `test_audit.py` smoke test passes (record,
  verify, export all 4 bundle files, tamper-detect both directions), CLI `--version` returns
  `arcaeon-audit 0.1.1`.
- **Scope discipline:** no new features — checked whether `export_bundle` should reference
  arcaeon-ledger 0.5.x's witness features and deliberately left that alone (new-products-over-
  polish rule); this release only fixes the broken import.

## v0.1.0 — 2026-08-13 (initial build)
- **What:** Article-12-in-a-box — the flagship of the evidence-layer strategy. A thin,
  tamper-evident **agent audit log** on top of arcaeon-ledger, plus a **regulator-ready
  export bundle** (records + integrity report + manifest + Article-12 mapping).
- **Why:** deep research (2026-08-13) found the evidence/provenance layer is the underserved,
  regulation-forced whitespace — EU AI Act Article 12 (applicable 2026-08-02) mandates
  automatic tamper-evident logging for high-risk AI, and the pattern is hash chains = our Ledger.
- **Design:** `AuditLog` wraps `ledger.Ledger`; `record()` captures agent events with the
  Art.12-relevant vocabulary (system_start/stop, input, tool_call, decision, human_review...);
  `export_bundle()` emits a self-verifying folder anyone can re-verify with arcaeon-ledger.
  Honest scoping: it's the integrity+export primitive, NOT legal advice / compliance-in-a-box.
- **Verified:** smoke test passes — 5-event log records, exports all 4 bundle files, flags
  unknown event types, and catches tampering both directions (verify flips False, names the
  exact broken row). CLI (`verify`, `export`) confirmed.
- **Open:** publish to PyPI (held for Daniel's glance — public product debut under Arcaeon),
  GitHub repo, tests dir, MCP-server wrapper.
