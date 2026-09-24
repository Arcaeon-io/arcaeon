# Changelog — arcaeon-baseline

## 0.1.9 — 2026-09-01: sell-code audit — the documented opt-out crashed, probes failed after the runner was paid, and the CLI hid two verdict fields

Internal audit of the published package, hunting defects a normal caller
reaches. Every fix below was reproduced first, then fixed, then pinned by a
test that was watched failing against the 0.1.8 source. Suite 90 -> 100.

- **`ledger_path=""` — the documented opt-out — crashed the library.**
  `compare()`'s own invalid-reasons say "pass ledger_path='' to compare()
  explicitly to skip this check". The CLI mapped `''` to None; the library
  did not: `Path("")` is the current directory, `.exists()` is True, and
  `Ledger("")` raised `PermissionError: '.'` — from both `register()` and
  `compare()`. So the one escape hatch offered to an honest unchained user
  did not open. Both entry points now treat `""` as None
  (`_ledger_opt_out`). The earlier `..lock` file this left behind in the
  working directory is the same bug's footprint.
- **A probe with a missing or mistyped `answer` loaded fine and crashed
  AFTER the runner had been called.** `exact_match` without `answer`
  (KeyError), `exact_match` with `"answer": 42` (TypeError inside the
  regex), `numeric_tolerance` with `"answer": "forty"` (ValueError) — all
  raised inside `score_item()`, which runs outside `run_probes`' error
  handling, so every item already answered was thrown away, and with a
  paid API behind `--cmd` that is real money for nothing. Validation now
  happens at load time with the `file:line` error every other malformed
  row gets. Rules are explicit, not widened: `exact_match` needs a string
  answer; `numeric_tolerance` needs a numeric `answer` (and `tolerance`, if
  given — bools rejected, numeric strings still accepted as before);
  answerable `calibration` needs a string answer and `answerable` must be a
  bool. Both shipped probe sets and the Hypothesis probe generator already
  satisfy all of it.
- **A runner returning a non-string crashed the batch.** A custom `Runner`
  or a `CallableRunner` wrapping an SDK call that hands back a response
  object / None / an int raised TypeError in the scorer, not RunnerError,
  so the whole run died instead of one item being recorded as an error.
  Now recorded as `error: "runner returned <type>, not str"` with
  `score: None`, exactly like a crash or timeout.
- **A runner output containing a lone surrogate made `register()` die at
  `write_text()`** — after every runner call had been made, and before the
  ledger row was chained. Now normalized to U+FFFD, the same treatment
  `CmdRunner` already gives undecodable bytes (`errors="replace"`). The
  matching probe-file case (a `"\udc80"` JSON escape in a prompt or
  answer) is rejected at load with a named reason.
- **A pathologically nested probe line raised a bare RecursionError**
  instead of the `file:line` ValueError promised for every other bad row.
- **`compare()` on a non-object registration JSON raised AttributeError**
  (`'list' object has no attribute 'get'`) instead of the "not an
  arcaeon-baseline registration" ValueError the next line promises.
- **CLI honesty: `compare` never printed `chain_check` or the coverage
  note.** The report has carried `chain_check` since 0.1.6 and
  `verified_scope`/`coverage_note` since 0.1.5 — the whole point of both
  was that "the silence was the defect" — but the terminal output for a
  diff whose tamper check was skipped, or that scored half the probe set,
  was identical to a fully verified one. The CLI now prints
  `chain_check: <status>  verified_scope=<scope>` and the coverage note.
- **CHANGELOG correction.** The 0.1.6 entry says the absent-ledger case
  "still returns `valid: True`" and lists the status as
  `skipped_ledger_file_absent`. Neither has been true since commit
  `d190e22` (2026-08-29, "P0: an unverifiable registration no longer
  reports valid=True"): a requested-but-missing ledger is
  `valid: False`, `invalid_kind: chain_ledger_absent`, `chain_check.status:
  ledger_file_absent`. The code was right and the changelog lagged; stated
  here rather than rewriting 0.1.6.

**Checked and clean:** version parity (pyproject / `__version__` / CLI
`--version` all agreed at 0.1.8), path handling (`_slug` strips separators
from labels; no traversal via `--out`/`--label`), no eval/exec/pickle, the
tamper chain (`items_digest` round-trip, absent/unlocatable/broken/
unverifiable ledger states), README claims vs. code (the "tamper-evident"
claim is backed by the chained `items_digest` check; "verified" is only
emitted when the digest was actually recomputed).

**Noted, not changed:** `runner.describe()` records the full `--cmd` string
into the registration file and the ledger row. A command line that embeds
an API key (`curl -H "Authorization: Bearer ..."`) is therefore copied into
both. That is the user's own command on the user's own disk, and redacting
by pattern is the kind of heuristic this package avoids — but a wrapper
script that reads the key from the environment is the safer shape, and the
README should say so in a later pass.

Published to PyPI 2026-09-02.

## 0.1.8 — 2026-08-30 — the sdist fix landed broken, and it was still too narrow

Closing out 0.1.7, which fixed the instance colonist-one reported (external
audit) but not cleanly: it shipped with `__version__` still reading `0.1.6`
against a `pyproject.toml` declaring `0.1.7` — the exact "bump touched one
file, not the other" defect `test_dunder_version_matches_pyproject` exists to
catch, and it went out uncaught because that test was never run after the
bump. `py -m pytest` on this repo was `1 failed, 87 passed` before this entry.
Fixed: `__init__.py` now reads `0.1.8`, matching pyproject.

**Second problem, same allowlist:** in narrowing the sdist include list down
to "only these ship," 0.1.7 also dropped `probes/` — real content, not a
cache. README.md says outright "Two starter sets ship in `probes/`," and the
CLI's own module docstring uses `--probes probes/` as the worked example.
0.1.4's sdist (the one with the .hypothesis cache) still carried `probes/`
correctly, because it swept the whole tree; 0.1.7's explicit allowlist
un-shipped it by omission. An allowlist that is too narrow fails the same way
one that is too wide does — it ships the wrong file set — it just fails
quiet instead of loud. `probes/` is back on the list in `pyproject.toml`,
named explicitly like everything else there.

**Reproduced the original report directly** by building the actual 0.1.4
commit in a worktree: with no `[tool.hatch.build.targets.sdist]` target,
hatchling ignores `MANIFEST.in` (inert under hatchling) and sweeps the whole
working tree. Building it here reproduced the mechanism exactly — a live
`.hypothesis/` cache dominating the sdist (262 of 284 members, 92.3%, in this
run; colonist-one's published number was 300 of 322, 93.2% — the gap is
ordinary Hypothesis cache-size drift between runs, not a different bug).

**The gate is now allowlist-shaped, not denylist-shaped.** `test_sdist_
hygiene.py` previously asserted the sdist didn't contain a fixed list of
*known* bad directory names (`.hypothesis/`, `__pycache__/`, etc.) — the same
shape of gap the packaging bug itself had: it only catches what someone
already thought to name. Added `test_top_level_allowlist_is_exhaustive`,
which asserts every top-level sdist entry is in an explicit allowed set
mirroring `pyproject.toml`'s include list — a workspace cache with a name
nobody has used yet (`.tox/`, `.ruff_cache/`, `.mypy_cache/`, whatever comes
next) fails this the same way `.hypothesis/` did, without being named first.
Added `test_ships_documented_probe_sets` so the probes/ omission itself has a
standing regression test. The old named-cache test stays as a belt-and-braces
check.

**Mutation-verified, both directions.** Stripped `pyproject.toml`'s
`[tool.hatch.build.targets.sdist]` block entirely (simulating the pre-fix
state, with a live 290-file `.hypothesis/` cache still present on disk):
`test_sdist_ships_no_caches_and_stays_small` and `test_top_level_allowlist_is_
exhaustive` both failed, the allowlist test naming `.hypothesis` directly
among the unexpected entries. Restored the fix: all three tests green again.

**Final numbers.** sdist: 21 members (was 300+ `.hypothesis` files alone
under the bug). Wheel: 11 members. Full suite: `90 passed` (was 87 passed / 1
failed with the version defect present). Published to PyPI 2026-08-31; publish window +
Daniel's blessing handles that, per standing process.

*Reported by colonist-one (external audit).*

## 0.1.6 — 2026-08-28 — the tamper check could be disabled with one `rm`, silently

The B-1 family, third pass, from an external audit of the published package.
Everything additive; no existing key changed shape and no verdict flipped.

**The hole.** `compare()` guards its registration-tamper check behind
`if ledger_file.exists()`. If the ledger is absent the entire check is skipped
with no trace anywhere in the output, and the run then chains its own row on the
way out — so the ledger is RE-CREATED by the very comparison that skipped the
check, and what is left on disk looks freshly chained.

Demonstrated end to end: register a baseline, edit the registration file's
`items[0].score` and its `aggregate.mean`, delete `ledger.jsonl`, compare. With
the ledger present this is caught (`invalid_kind: registration_tampered`).
Without it: `valid: True`, an ordinary clean diff, reporting a fabricated
**+0.5** improvement, with nothing in the report saying the check never ran.

This is the same defect shape as 0.1.3's B-1 (matched by path STRING, so a
differing path form silently skipped the check) and 0.1.4's B-1 RESIDUAL (a
differing cwd meant no row matched, so the check silently skipped). Both fixed an
inner gate. The outermost gate — "is there a file at all" — was never closed, and
it is the one an attacker reaches first. 0.1.4's own comment already stated the
rule this violated: *"`ledger_path` defaults to a real path (chain verification is
requested unless the caller explicitly opts out) … so if no row can be found for
this specific registration, that is now UNCONFIRMABLE, not confirmed-clean."*

**Added: `chain_check` on every comparison report** — `{ran, status, detail}`,
answering the question `valid` never did: did the tamper check actually RUN?
`status` is one of `verified`, `skipped_ledger_file_absent`,
`skipped_no_ledger_path`, `skipped_row_predates_items_digest`,
`registration_tampered`, `chain_unlocatable`, `ledger_broken`,
`ledger_unverifiable`. A skipped check is now visible to a reader at a glance;
before this it was invisible at any level of diligence.

**NOT changed, deliberately, and flagged for a decision:** the absent-ledger case
still returns `valid: True`. Flipping it would be the security-correct call and
matches the discipline 0.1.4 already applied to `chain_unlocatable` — but it turns
a currently-passing comparison into `valid: False` for anyone whose ledger is not
where `compare()` looks, so it is named here rather than taken silently. The
documented opt-out (`ledger_path=""`) already exists for callers who mean it.

**Fixed: an unverifiable ledger was accused of being a BROKEN one.**
`Ledger.verify()` has been tri-state since arcaeon-ledger 0.5.7 — `ok=None` means
"no fault found, but the scan did not cover everything" (an empty file, unchained
prechain rows, a declared break). `if not chain_verify.ok` swept that into the
accusation *"the ledger … no longer verifies (broken chain)"*. The verdict was
right for the wrong reason: such a comparison IS invalid (a scan that did not
cover every row cannot confirm this registration), but the operator was handed a
false charge against their file. Now `invalid_kind: ledger_unverifiable`, naming
the scope and saying plainly that no fault was found. `valid` unchanged in both
directions; `ledger_broken` still means a real break.

Three tests, each watched failing first. Suite 84 -> 87.

NOT PUBLISHED — local commit only.

## 0.1.5 — 2026-08-28 — a comparison that could not score every probe now says so

`valid` and "clean" were being read as the same word. They are not. `valid`
answers whether the exam stayed the same underneath you -- same probe set, same
scoring semantics -- and it has never answered whether every probe was actually
scored.

**A model that started REFUSING half the probe set produced a perfect no-drift
report.** Measured: `valid: True`, `n_flips: 0`, `aggregate_after.mean: 1.0`,
off a run that scored one probe out of two. Three mechanisms line up to hide it,
each individually reasonable:

  - `run_probes` records an unanswerable probe with `score=None` and
    deliberately does not abort the batch (correct -- one flaky call should not
    cost the whole run);
  - a flip is a CHANGE in score, and a probe unscored in both runs compares
    `None` to `None`, which is never a change, so it can never flip;
  - the mean is computed over `n_scored`, so it stays 1.0 while probes go
    unanswered.

The evidence was already in the report the whole time, in
`aggregate_after.n_errors`, and nothing in the verdict read it. Downstream this
is not theoretical: arcaeon-continuity 0.2.2 had to fence exactly this at its
own layer, because a snapshot built on an unscorable probe minted
`faithful=True, comparison="exact_match"`. The root of that lives here.

**New fields, both additive; no existing key changed shape.**

  - `verified_scope` — `"full"`, `"bounded_after_unscored"`,
    `"bounded_before_unscored"`, or `"bounded_both_unscored"`. Same vocabulary
    arcaeon-ledger uses for the same question, so the family answers coverage
    in one language.
  - `coverage_note` — one sentence naming how many probes went unscored on
    which side, or `None` when coverage is full. The silence was the defect: a
    partial run produced a report textually identical to a complete one.

**`valid` is deliberately unchanged.** A bounded comparison really was valid;
it simply did not cover everything. Flipping `valid` to `False` would conflate
"the exam changed" with "some probes did not answer" and would break every
existing `if report["valid"]` in the wild. The honest reading is `n_flips`
covers `verified_scope`, not the whole probe set.

Suite 81 -> 84. Each new test watched failing first.

## 0.1.4 (2026-08-28)
- Packaging hygiene only, no code changes: the 0.1.3 sdist accidentally shipped a .cleanverify/ virtualenv (512 files under site-packages, vendored pip) - the workspace of the clean-room verification step, shipped inside the artifact the step was certifying. Found by colonist-one in the 8/27 reciprocal audit (comment 446d03bc), adopted and fixed: workspace removed, MANIFEST.in prunes added, sdist contents verified by listing before upload. Wheels were always clean; sdist consumers (--no-binary, platforms without the wheel) were affected.

## 0.1.3 — the tamper check matched by path STRING, not by file (product audit 2026-08-23, B-1)

`compare()`'s ledger-chain tamper check (0.1.2) only ran if the row's
`registration_file` string-matched `--against` byte for byte. `register()`
records whatever form `out_dir` was given — this CLI's own default and
module docstring example is a relative `registrations/` — and any caller
passing `--against` in a different but equivalent form (an absolute path,
the ordinary shape once a script resolves what register() handed back)
silently skipped the ENTIRE tamper check, not just the string match: no
warning, `matches` came back empty, and a forged registration file was
scored as a genuine `valid: True` diff. This is the flagship
"tamper-evident" guarantee voided by realistic, non-adversarial usage.

**FIXED**: both sides now resolve to their canonical absolute path
(`Path(...).resolve()`) before comparing, so the match is by FILE, not by
whichever string happened to reach `compare()`. Mutation-verified: reverted
to the old string-equality match, confirmed the new regression test fails
by scoring tampered content `valid: True`, restored. 79/80 (one pre-existing,
unrelated Hypothesis test-fixture gap in the unicode-line-separator suite —
an answer that normalizes to empty string via `score_exact_match`'s own
documented behavior — reproduces identically before this fix and is not
this package's shipped defect; noted, not fixed here).

## Unreleased — property-test hardening (Hypothesis)

Test-hardening pass, no version bump. Added `test_hypothesis_baseline.py`
(12 Hypothesis property tests: registration determinism + the module's real
order-sensitivity contract, scoring determinism, forged-probe/tamper
detection, and the U+0085/U+2028/U+2029 unicode-line-separator class).

- **Fixed: `load_probes()` broke on U+0085/U+2028/U+2029 in probe text.**
  Read `.jsonl` probe files with `text.splitlines()`, which treats these
  three characters as row breaks even though `json.dumps(...,
  ensure_ascii=False)` (the natural way to author a probe file) does not
  escape them — a well-formed probe whose prompt or answer legitimately
  contained one raised `ValueError: ... Unterminated string` on load, or
  worse, silently mis-split into the wrong number of records. Fixed by
  switching to `text.split("\n")`, matching the already-fixed idiom in
  `arcaeon-ledger`'s `Ledger.__iter__`/`verify_file`.
- **Fixed: `compare()` had no defense against a directly-edited registration
  file — the highest-severity gap this package could have.** The whole
  point of arcaeon-baseline is catching a substrate swap that quietly
  changed something; `compare()` trusted `reg["items"]`/`reg["aggregate"]`
  straight off disk with zero verification, and the ledger only ever
  chained the aggregate *mean* (a single float), never the per-item content.
  Editing the registration JSON on disk — flip a wrong item's score to
  correct, swap two items' scores so the mean is unchanged, truncate the
  set — was silently accepted and reported as an ordinary `valid: True`
  diff, using the forged "before" value as ground truth. Fixed: `register()`
  now chains a content digest (`items_digest`, over the full items +
  aggregate) into the ledger alongside the existing summary fields;
  `compare()` recomputes and checks it against the chained value before
  trusting the file, and refuses the diff on any mismatch or on a broken
  ledger chain. Known, stated boundary: this closes the hole for *chained*
  registrations (the normal case); a registration made with
  `ledger_path=None`, or compared against the wrong/missing ledger file,
  has nothing to check against — same honest limit a hash chain always had.

## 0.1.2 — 2026-08-14 — comparison validity + scoring boundaries (hostile audit)

A deliberately hostile audit of the scorer, including the 0.1.1 fix below. The headline finding is a **silent wrong answer in the tool's core question**, and it was created by 0.1.1 itself.

- **`compare()` reported the SCORER's own version change as a substrate change, with `valid: True`.** The probe-set digest guards the exam from changing; nothing guarded the scorer. `compare()` re-runs the probes and re-scores them with whatever version of this package is installed *now*, then diffs against scores frozen into the registration file by whatever version was installed *then*. Upgrade in between and the scorer's behaviour change is attributed to the substrate. This was not hypothetical: **0.1.1 changed calibration scoring** (a hedge-wrapped correct answer moved from the 0.2 abstention floor to 1.0), so every 0.1.0 registration compared under 0.1.1 shows improvement no model produced. Demonstrated with a runner returning byte-identical output on both sides — nothing about the substrate changed at all — and 0.1.1 reported `n_flips: 1`, `aggregate_delta.mean: +0.8`, `abstention_rate_answerable: 1.0 -> 0.0`, `valid: True`. Registrations now record `scoring_semantics` (`arcaeon-baseline:scoring:v2`) and `tool_version`; `compare()` **refuses to produce a diff** across a semantics change or against a pre-0.1.2 registration that cannot name its scorer, exactly as it already refuses across a changed probe set. Refusing is the honest output; a number nobody can interpret is not.
- **The sibling hole 0.1.1 opened, now closable per probe.** Routing calibration through `score_exact_match` inherited containment matching's weakness: `"I'm not sure. It could be London, Paris, Berlin, or Rome"` **contains** the correct answer, so it scored **+1.0**. Under 0.1.0 that same output scored +0.2. The anti-gaming fix therefore *raised* the payoff of enumerate-everything from the abstention floor to full credit. Probes may now declare `distractors` (known-wrong answers); an output containing the answer **and** a declared distractor scores the abstention floor with `shotgun: True` in the detail. Opt-in, no behaviour change when absent, and it does not punish a genuinely hedged-correct answer.
- **Numeric false positives, both directions.** `_NUM_RE` (`-?\d+\.?\d*`) matched fragments of larger numbers: `"The answer is 1,000"` scored **CORRECT for an expected 0** (matching the `000` after the comma) and `"It is 1e5"` scored **CORRECT for an expected 5**. The pattern now understands sign, thousands grouping, decimals and exponents, and refuses to start or end inside another number — so `1,000` reads as 1000 and `1e5` as 100000. Separately, `score_exact_match` credited `"40"` against `"The result is 40.5 units"` and `"3.14"` against `"version 3.14.15"`, because `(?!\w)` does not stop at a decimal point; token boundaries are now digit- and decimal-aware. A scorer that credits a wrong answer is worse than one that credits nothing.
- **Honest limits restated, not papered over:** a hedge-wrapped wrong guess that is neither the answer nor a declared distractor still reads as a plain hedge, and negation is unhandled — `"it is definitely not Paris"` still reads as Paris. Both would need free-text guess extraction, which this module deliberately does not build.
- Twenty-four regression tests added (`test_scoring_integrity.py`), each written failing first; `python -m arcaeon_baseline.selftest` gained the enumerate-everything and numeric-boundary sections so both are observable without trusting our CI.
- **If you hold a registration made with 0.1.0 or 0.1.1, re-register a fresh baseline.** Its scores were produced by a scorer that no longer exists, and this version will (correctly) refuse to diff against it.

## 0.1.1 — 2026-08-14

**Fix: hedge-wrapped-answer gap in the calibration abstention guard.**
Found via our own abstention-gaming research (`RESEARCH_43`, 2026-08-14 —
not an external report). `score_calibration()` checked `is_abstention(output)`
FIRST and short-circuited to the `idk_answerable` floor (0.2) whenever a
hedge phrase matched — WITHOUT ever checking whether a correct answer was
also present in the same output. Concretely: `"I'm not sure, but I think
it's Berlin"` (wrong, if the answer is Paris) and `"I'm not sure, but I
think it's Paris"` (correct) scored identically, because the embedded guess
was never read once the hedge regex fired. Incentive math: this guaranteed
a score floor for any wrong answer under ~60% self-confidence, just by
wrapping it in hedge phrasing — a gameable guard in a product whose pitch
is anti-gaming.

**The fix:** attempt `score_exact_match` against the full output *first*,
even when hedge language is present; only fall back to the abstention score
when no matchable answer is found in the text.

**What this closes:** a hedge-wrapped answer that IS the correct answer now
scores `correct` (+1.0), not the abstention floor — the guard can no longer
be defeated by wrapping a right answer in defensive hedge language to farm
a "safe" score instead of claiming full credit (not the exploit direction
that mattered, but it proves the correctness check now runs).

**What this does NOT close (documented, not silently left):** a
hedge-wrapped answer that is WRONG, and does not happen to contain the
correct answer text, still lands on the `idk_answerable` floor (0.2) —
same as before. This scorer has no way to detect that a wrong guess is
embedded in a hedge (as opposed to no guess at all) without either a bank
of known-wrong distractors per probe (not part of the current probe
schema) or free-text guess extraction — which is exactly the NLP-guesser
this module deliberately does not build, to keep scoring conservative and
deterministic. Closing this fully would require a structured, always-
emitted confidence field (per arXiv 2608.00301) or a per-probe distractor
list — both bigger scope changes than this patch. The remaining gap is a
narrower exploit than the one fixed: it only pays off for a wrong guess
that a test-writer never listed as the correct answer, and the fix already
removes the free ride for the case that mattered most (the always-safe
floor regardless of correctness).

**Test coverage:** `test_scoring.py` adds a hedged-correct fixture (fails
against the pre-fix code, passes after), a hedged-wrong fixture (pins the
documented remaining gap — asserts it still scores the idk floor, so a
future change to that behavior is a deliberate decision, not a silent
regression), and a fixture proving the two are no longer indistinguishable.
`python -m arcaeon_baseline selftest` plants a hedge-gaming case and prints
both the catch and the documented gap note.

**README:** added the literature's real headline finding (arXiv 2511.11500
— frontier models "almost never abstain despite explicit warnings of
severe penalties," i.e. the dominant real-world failure is confident-wrong,
not hedge-farming) to the calibration guard section, so the guard is
positioned honestly as defending a secondary risk, not oversold as the
primary one.

## 0.1.0 — 2026-08-14

Initial release. Pre-registered probe sets for substrate-transition measurement.

- `register(probes, label=..., runner=...)` — runs a probe set, scores it, writes
  a registration file (probe-set digest, per-item scores, aggregate, timestamp),
  and chains a record into an arcaeon-ledger file. The pre-registration is the
  timestamp.
- `compare(against, runner=...)` — re-runs the same probes, verifies the
  probe-set digest still matches the registration (a changed exam invalidates
  the comparison and says so, rather than producing a misleading diff), and
  reports per-item flips, an aggregate delta, a calibration shift when the
  set has calibration items, and an honest "n too small for significance"
  note when the sample can't support one.
- Pluggable `Runner`: `CmdRunner` (shell out — prompt on stdin, answer on
  stdout, works with `ollama run <model>`, a wrapped API script, any CLI),
  `CallableRunner` (wrap a Python function, no subprocess), or subclass
  `Runner` directly for anything else.
- Two starter probe sets ship in `probes/`: `reasoning.jsonl` (15 short
  deterministic-answer items, `exact_match`/`numeric_tolerance` scoring) and
  `calibration.jsonl` (15 items, mixed answerable/unanswerable, `calibration`
  scoring with an abstention-gaming guard — honest IDK scores well but not as
  well as answering correctly, so an always-abstain strategy can't top the
  aggregate on a mixed set).
- CLI: `python -m arcaeon_baseline register|compare|selftest`.
- Bundled self-test (`python -m arcaeon_baseline selftest`) runs entirely
  in-process — no subprocess, no network — so a stranger can trust their own
  run of it.
- Design credit: pre-registering a self-experiment before a substrate change
  is inspired by a public pre-registered self-experiment by the agent
  rosetta on The Colony (2026-08-14); the calibration abstention-gaming
  guard honors the design point from our own submission to Verigent's
  calibration exam (verigent.ai/open-challenge).
