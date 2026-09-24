# Changelog

## Unreleased

### 2026-09-23 (branch reconcile-hardening-2026-09-23): witness_self_integrity's default was a fourth, undocumented value

* **Why.** `WitnessVerdict.witness_self_integrity` (`witness.py`) is documented, in its own docstring and in the README, as exactly three values: `verified`, `unestablished`, `broken`. The dataclass field declared its default as `"unknown"` — a fourth value nobody wrote a reader for. Every path `verify_against_witness()` actually takes already sets the field itself (through the internal `_V()` helper) to one of the three documented values, so `"unknown"` only ever surfaced when a `WitnessVerdict` was constructed directly, bypassing that helper — which is a real, reachable path: `WitnessVerdict` is exported in `__all__`, and the suite itself does this once (`test_conformance_failure.py`'s lying-verifier stand-in).
* **Now the default is `"unestablished"`** — the honest reading of "we did not establish it," and already the value every no-`verify()` code path reports. No reader in the tree branches on `"unestablished"` as a positive claim (it is bounded/falsy by design, same as the rest of this module's three-valued verdicts), so the safer of the two ticket options — required field vs. honest default — was the default change; nothing on the wire changes (no verdict is serialized into a bundle or receipt today) except the value a caller sees if they build a verdict without naming the field.
* **Tests** (`test_witness_chain.py`): `test_witness_self_integrity_every_constructor_path_is_documented` builds a `WitnessVerdict` every way this codebase does — the bare constructor with and without the kwarg, and `verify_against_witness()` through a self-verifying `WitnessStore`, a `.latest()`-only hosted-shaped client, and a client whose own `verify()` reports broken — and asserts each lands in `{verified, unestablished, broken}`. `test_witness_self_integrity_default_is_unestablished_not_unknown` pins the bare default itself. No existing test asserted `"unknown"`, so none needed updating.

### 2026-09-23 (evening): the bundle README names exit 3

* **Why.** The auditor bundle's README told a stranger "exit 0 = VERIFIED, 1 = BROKEN" for the reproduce command, but `arcaeon-ledger verify --strict` also exits 3 (ok=null), for example on an empty ledger. The line now reads "exit 0 = VERIFIED, 1 = BROKEN, 3 = COULD NOT LOOK." Text only (`bundle.py`); no exit code, field or verdict value moved.

### 2026-09-23 (branch reconcile-hardening-2026-09-23): reconcile never raises

* **Why.** The Node port of reconcile (arcaeon-witness `lib/_reconcile_tapes.js`, `RELEASE_NOTES_reconcile_2026-09-23.md`) found three inputs on which `reconcile.py` raised a traceback instead of answering: (1) a line with a duplicate key that then fails to parse (`{"a":1,"a":2} x`): `verify_file`'s `except DuplicateKeyError` re-parses and the `JSONDecodeError` escapes; (2) a row that verifies but is wrapped in whitespace `str.strip()` removes and `json.loads` does not (`\x0b \x0c \x1c-\x1f \x85 \xa0 U+2028 U+3000`): `_load`'s second read raised; (3) a line nested past CPython's C recursion guard reaching `_peek_side`, which caught `ValueError` and not `RecursionError`. A verdict tool that one planted line can turn into a crash is not giving a verdict.
* **Now each is COULD NOT LOOK (exit 2), naming the line or row and the cause in brackets**, in the port's words as far as they are true here: `tape_a line 6 holds a duplicate key and does not parse [duplicate_key_unparseable]`, `tape_a row 2 verifies but does not read a second time (whitespace json.loads does not strip) [whitespace_outside_json]`, `tape_a line 1 is nested deeper than 512 levels [nesting_too_deep]`. Where the port says "the reference implementation raises on this line instead of answering", reconcile.py no longer does, so it does not say it.
* **Nesting is bounded at 512 levels**, as in the port (`reconcile.MAX_DEPTH`): a line whose parser opens more than 512 arrays/objects before it stops is COULD NOT LOOK `[nesting_too_deep]`, never a guess. CPython's own ceiling moves with platform and version; a tape row is flat. A 513-deep line that 0.8.0 read as a break (ALTERED) or inside a valid row (MATCHED) is now COULD NOT LOOK.
* **A fence:** anything that still raises inside `reconcile()` answers COULD NOT LOOK `reconcile could not finish: <ExceptionType> [internal_error]` (the exception's message is not echoed). `_peek_side` also skips a line that raises `RecursionError`, and a pin file nested past the C guard is `pin unreadable: ... [nesting_too_deep]`.
* `verify_file` itself is unchanged: called directly (`arcaeon-ledger verify`), input (1) still raises there. Named, not fixed in this entry.
* **Tests:** `test_reconcile_hardening.py` (28): each of the three inputs reproduced first (the pre-fix traceback is in each test's docstring), the 512/513 boundary, objects counted and brackets in strings not, a syntax error before the nesting not counted, first bad line wins, a fuzz of 500 seeded byte and Unicode mutations of an honest pair (every one returns a verdict dict, none reaches the fence), a pin file nested past the C guard, and the fence itself. Existing suite unchanged.
* **Cross-repo conformance** (arcaeon-witness `test/fixtures/reconcile/cases.json`, 493 cases): re-judged with this reconcile.py, 483 answers are byte-identical to 0.8.0's; the 9 cases recorded as `python_raises` now have an answer (COULD NOT LOOK, same counts and fields as the port's, reason wording differs as above), and `nested_522_both` moves from MATCHED to COULD NOT LOOK `[nesting_too_deep]`, which is what the port already said. The fixture and the port's `REFERENCE.reconcile_sha256` live in that repo and are not changed here.

## 0.8.0 — 2026-09-23: `reconcile` and the tape (a COMPLETENESS verdict), one set of verdict words, and the pre-commit receipt hook

Everything below this heading down to 0.7.5 was staged as dated Unreleased entries between 2026-09-05 and 2026-09-23 and ships together in 0.8.0. The companion `arcaeon-adapter` ships as 0.2.0 from the same tree (see `adapter/CHANGELOG.md`).

### 2026-09-23 (branch completeness-slice3): an invalid id is a row, not a gap

* **Why.** The adapter dropped a `tools/call` with a boolean id while arcaeon-receipt's call_proxy taped it, so a clean stream carrying `id: true` reconciled MISSING on the agent side.
* **The rule, both tapes:** JSON-RPC 2.0 ids are string, number or null. A `tools/call` with any other id (true, false, object, array) is taped at once with `status: "invalid_id"`, `resp: null`, and never paired with an answer; a null or absent id is still a notification. `reconcile` is unchanged: the two identical rows match. Detail and tests in `adapter/CHANGELOG.md`; cross-repo ids [true, 1, "x"] reconcile `MATCHED 3 of 3`.

### 2026-09-23 (branch completeness-slice3): no call lost to a reused id

* **Why.** A reused JSON-RPC id made the adapter overwrite the first call's pending slot: that call vanished from the seam log, its tape row stayed open until session end, and the second call was taped with the first call's answer, while arcaeon-receipt's call_proxy taped the first answer for both. See `adapter/CHANGELOG.md`.
* **The rule, both tapes:** open calls are queued per (scope, id) in send order; an answer pairs with the OLDEST open call of its id; a call never overwrites another; every sent call gets exactly one tape row and one seam row; a call still unpaired at session end is `unanswered`. With the matching arcaeon-receipt change, a batch with ids 1,1,2 reconciles `MATCHED 3 of 3`. Also: the HTTP forward mode no longer forwards a header named in `Connection` (RFC 9110 7.6.1). Root suite 604 passed, 4 xfailed, unchanged.

### 2026-09-23 (branch vocabulary-2026-09-23): one set of verdict words

* **Why.** The Fable audit (2026-09-22) found four verdict languages across the Arcaeon tools. The helm's decision: VERIFIED for a pass in one run, BROKEN for a failure, COULD NOT LOOK for "did not get to look", on every surface; `reconcile` already spoke MATCHED / MISSING / ALTERED / COULD NOT LOOK and is unchanged (a match is a verdict about two records agreeing, a different question).
* **`verify` help text and README exit table:** exit 0 is VERIFIED, 1 is BROKEN, 3 is COULD NOT LOOK at every row (was "fully verified / broken / verified within scope only"). Exit codes and every JSON field (`ok`, `verified_scope`, `prechain`, `breaks`) are unchanged.
* **Evidence bundle README headline:** VERDICT: VERIFIED (was "intact"); the adoption case leads with COULD NOT LOOK at every row, then VERIFIED from adoption onward only; the bounded case is COULD NOT LOOK at every row. BROKEN and EMPTY unchanged. `verify_report.json` (including `exit_code_semantics`) is unchanged: it is a machine file.
* `selftest` still prints PASS / FAIL: those are its own test results, not verdicts on anyone's log.
* Tests: `test_bundle.py` asserts the new headline words (four assertions updated, none deleted; the adoption guard now asserts the pre-chain region reads COULD NOT LOOK, was UNVERIFIED). Suite 795 passed, 6 skipped, 4 xfailed before and after.

### 2026-09-22 (branch completeness-slice3): the agent-side tape for HTTP MCP servers

* **Why.** Reconcile needs a tape at each end of a call. The adapter could only keep the agent-side tape for a stdio server, so an agent calling an HTTP MCP server had none, and the slice-two cross-repo demo needed a test-only bridge.
* **Adapter: `arcaeon-adapter --http-forward URL --listen HOST:PORT`** (see `adapter/CHANGELOG.md`). A local listener in front of the HTTP MCP endpoint; answers relayed byte-for-byte and streamed; tape rows with the same digests as the stdio path and arcaeon-receipt's call_proxy. The ledger library itself is unchanged.
* **The demo, no bridge:** client -> adapter --http-forward (agent tape) -> tamper hop -> call_proxy (tool tape) -> HTTP MCP server. `reconcile` says MATCHED 7 of 7 clean (JSON and SSE), ALTERED at call 2 when the hop changes one answer, MISSING at call 3 (tool tape) when the hop drops one request.
* **Review follow-up (same branch).** The forwarder no longer hangs the agent when the upstream's Content-Length lies short (it closes the agent's connection, as a direct call would end). With arcaeon-receipt `completeness-slice2` cae439e, the tool tape leaves a 202 open and reads gzip/deflate answers from a copy, as the adapter does, so a call answered later on the GET stream now reconciles `MATCHED 2 of 2` instead of reading as a disagreement.

### 2026-09-22 (branch completeness-slice2): the counter, pinned at the witness

* **Why.** Slice 1 made the tape a counter in principle (`rows` = calls, `chain` = head) but nothing pinned it. Without a pin, two tapes cut at the same point still match; the pin bounds that to "since the last pin".
* **NEW `arcaeon_ledger/tape_pin.py`: `pin_tape(tape, store, *, namespace=None, pair=None)`.** Pins a tape through the existing `publish_head` path, so the witness body is the one it already takes, `{namespace, rows, chain}`, and the existing refusals hold (an empty or unverified tape is never pinned). Tape-specific refusals run BEFORE any request: not an `arcaeon-tape/1` tape, mixed side or namespace, no namespace, a namespace that contradicts the rows, a malformed `pair`. Returns a pin record `reconcile --pin` reads directly.
* **NEW `witness.HostedWitness(url, key)` / `HostedWitnessError`.** The HTTP client half of the hosted witness (`POST {url}/api/pin`, bearer key). No default URL: nothing reaches a live service unless the caller names it. A pin whose echoed rows/chain differ from what was sent is an error, not a success.
* **The design's optional `pair` and `record_format` fields.** arcaeon-witness `api/pin.js` (read, not changed) validates only namespace/rows/chain and builds the stored pin from named fields, so unknown fields are ACCEPTED AND DROPPED; there is no metadata path. They are sent (harmless), then checked against the echoed pin and reported in `extra_fields`: `dropped_by_witness` today, `recorded` if the witness ever stores them, `refused_by_witness` (after ONE retry without them) if a witness 400s them, `not_sent` for a store that does not take extras. Never claimed as recorded when they were not.
* **`publish_head(..., extra=None)`**: passes `extra` only to a store that declares `accepts_extra = True`; every existing store gets the unchanged call.
* **NEW `test_tape_pin.py`** (21): against a mock witness on 127.0.0.1 with pin.js's rules (drop / keep / strict modes, monotonic 409, idempotent 200, bad key 401, unreachable, a witness that records a different head); the pin then catches a cut tape as MISSING in reconcile. Two break arms: a pinner one row short, and a client that claims extras were recorded.
* Adapter: `--pin-witness URL` / `--tape-pair` pin the tape head at session end (see `adapter/CHANGELOG.md`).

### 2026-09-22 (branch completeness-slice1): `reconcile`, a COMPLETENESS verdict from two tapes and a counter

* **Why.** `verify_file` proves a record was not altered. It cannot prove the
  record is complete, because one writer decides what to write. A tool call
  has two ends, so completeness can be checked where both ends keep a tape.
* **NEW `arcaeon_ledger/reconcile.py` and `arcaeon-ledger reconcile <tape_a>
  <tape_b> [--pin <pin.json>]`.** Reads two `arcaeon-tape/1` tapes (one row per
  call, in call order, digests of request and response as that side saw them;
  written by arcaeon-adapter `--tape`) and returns exactly one of MATCHED n of n
  (exit 0), MISSING at call k with the short side named (exit 1), ALTERED at
  call k (exit 1), or COULD NOT LOOK (exit 2), plus JSON listing every finding,
  what could not be checked, each pin's result, and the limits.
* **The tapes are lined up by request digest, not by row position.** Each side
  numbers its own calls, so one request lost in transit shifts the tool's
  numbering. A position-only walk would report every later call as ALTERED
  when exactly one is MISSING. A call found on both tapes at different places
  is ALTERED (order), not two MISSINGs.
* **The counter is the witness pin the witness already accepts.** A tape row
  is one call, so `{namespace, rows, chain}` is "count + head". `--pin` flags a
  tape holding fewer rows than pinned (MISSING) or a different chain at the
  pinned row (ALTERED, via `chain_at`). No witness change needed.
* **Stated limits, in every result:** a colluding pair can agree on a lie; a
  call that crossed neither seam is invisible; digests compare content, not
  bytes; without a pin, two tapes cut in agreement still match (pinned as a
  test).
* **NEW `test_reconcile.py`** (66 tests): 18 MISSING/ALTERED shapes (truncated
  tape, torn tail, dropped mid-stream, extra on the tool side, index gap,
  duplicate index, reordered rows re-chained and not, swapped content, edited
  row, lost response, altered request and response, empty tool tape, pin
  beyond both tapes, both tapes cut in agreement caught by the pin, tape
  rewritten after its pin), 6 COULD NOT LOOK shapes, positive controls, CLI
  exit codes, and two break arms: a reconcile that always says MATCHED fails
  all 24 failure cases, and one that files ALTERED as MISSING fails the five
  ALTERED cases it was run against.
* Design page: `projects/online_business/COMPLETENESS_DESIGN_2026-09-22.md`.

### 2026-09-19: a head over a BROKEN log no longer looks like a head over a NEW one

* **The bug.** Write the single line `{this is not a ledger row` into a ledger
  file. `verify_file()` gets it exactly right --
  `VerifyResult(ok=False, rows=0, first_break='line 1: unparseable')`. But
  `Ledger.head()` called `verify_file()` only to count rows and threw the
  verdict away, so it returned `Head(chain='genesis', rows=0, as_of=...)` --
  byte-for-byte the head of a log that had never been written to -- and
  `head().as_pin()` minted a clean genesis pin over the damage. A corrupted or
  truncated log was indistinguishable from a brand-new one at the exact place
  the library's answer leaves the building. In a tamper-evidence product that
  is the wrong default. (Found from arcaeon-receipt's side on 2026-09-19, while
  fixing its `/health` endpoint, which had inherited the same blind spot.)
* **`Head` now carries the verdict: two new fields, `ok` and `first_break`,**
  populated from the same `VerifyResult` `head()` was already computing. `ok`
  is three-valued exactly like `VerifyResult.ok` (True = every row checked;
  None = no break but the scan was bounded by skipped prechain rows or a
  declared break; False = a break, named in `first_break`). Both default to the
  green, so every existing positional and keyword construction of `Head`, its
  equality and its unpacking keep working untouched; only the repr grows.
* **`Head.as_pin()` and `publish_head()` REFUSE when the verdict is red,**
  raising the new `UnverifiedLedgerError`, whose message quotes `first_break`.
  A pin is the one artefact that goes somewhere outside your control, and its
  whole content is a claim -- "this log, at this height, at this time". Over a
  broken chain that claim is false, and it travels under this library's name.
  `UnverifiedLedgerError` subclasses `ValueError`, so callers already wrapping
  `publish_head` (it has refused zero-row pins with a `ValueError` for
  releases) catch it with no change. In `publish_head` the new check runs
  BEFORE the zero-row guard, because a corrupt file usually also has zero
  parseable rows and "line 1: unparseable" is the more useful refusal.
* **`head()` itself still does not raise, deliberately.** It is a read, and
  three things in this repo alone call it on the unhappy path -- the MCP
  server's `head_hash`, `verify_against_witness()` (which reports
  `local_broken`), the selftest -- plus dashboards and health endpoints
  downstream. A damaged log is precisely when those must keep answering; a
  reader that explodes tells you less than one that says "red, line 3". So the
  verdict rides on the value and the refusal happens one step later, where the
  head stops being an observation and becomes a published claim. This also
  means no existing caller of `head()` breaks: they see a new field or they see
  nothing.
* **A bounded verdict (`ok is None`) still pins**, and that is a decision, not
  an oversight. Bounded is not broken: the height and the tip are accurate and
  no break went unexplained. Refusing here would make any log that ever used
  `declare_break()` permanently un-pinnable -- punishing the honest repair and
  rewarding hiding the break instead.
* **An empty or not-yet-created log still pins as genesis, `ok=True`.** Two
  verdicts mean "nothing here" rather than "damage", and `head()` now tells
  them apart: an absent file (`verify_file()` has nothing to read and says
  `ok=False, unreadable: [Errno 2]`) and a zero-row file (`ok=None`,
  `verified_scope="empty"`, per 0.5.8). The absent-file test is
  `FileNotFoundError` specifically, not `Path.exists()`, which swallows every
  OSError and would have graded a permission-denied path "brand new" and let it
  mint a pin. A file whose only line is unparseable does not land here: zero
  rows, but `ok=False` and scope `"full"`.
* **NEW `test_head_verdict.py`** (10 tests): corrupt file, truncated-mid-row
  file, mid-file edit, `head()` still returning on all three, clean 3-row
  ledger pinning byte-identically to before, absent and zero-byte ledgers
  pinning as genesis, positional/keyword `Head` construction and equality,
  `publish_head` refusing, and `UnverifiedLedgerError` being catchable as
  `ValueError`. Plus a planted must-fail arm that asserts the OLD behaviour is
  gone; run against the pre-change module it goes red 8 tests of 10 (the two
  survivors are the deliberate invariants: `head()` not raising, and the error
  class being a `ValueError`), and under pytest the module does not even
  collect. Suite: 477 -> 487, all passing.

### 2026-09-12: L-011 through L-015, the pre-commit receipt hook

* **NEW `hooks/receipt_diff.py`.** A pre-commit hook that mints a best-effort
  arcaeon-ledger receipt over `git diff --cached` before each commit, appending
  to `.arcaeon/receipt_diff.ledger.jsonl`. Self-contained (puts this repo's
  root on `sys.path` itself so nothing needs installing first); depends only
  on `arcaeon_ledger` (`bind_artefact`, `Ledger`), not on `arcaeon-receipt` --
  consistent with this repo's zero-coupling note above (B-008) and its own
  zero-dependency stance.
* **The trade-off is load-bearing, not incidental:** every failure path
  (git diff fails, digest fails, ledger append fails) is caught, warned to
  stderr, and the process still exits 0 -- past argument parsing there is no
  code path that returns nonzero. A hook that can block a commit gets
  `--no-verify`d into silence; this one can't, on principle.
* **Bypass/gap detection, the actual point of the file:** each row records
  `extra.parent_head` (the `git rev-parse HEAD` seen at hook-run time). The
  next run compares current HEAD against it, subtracts the one commit a
  normal (non-bypassed) run between two hooks accounts for, and reports the
  remainder as `"N commit(s) since the last receipted diff"` in both the new
  row (`extra.gap`) and stderr -- so `--no-verify` shows up as a labelled
  number on the next commit rather than a quiet reset to clean. Adopting the
  hook onto a repo with pre-existing, un-receipted history reads the same way
  (a gap from commit one), never as a fresh clean start.
* **NEW `.pre-commit-hooks.yaml`** defines the `arcaeon-receipt-diff` hook
  (`language: system`, `entry: python hooks/receipt_diff.py`) for downstream
  repos to adopt as a pre-commit source.
* **NEW `test_receipt_diff_hook.py`** (11 tests, real git repos in `tmp_path`,
  no mocked git): nothing-staged skip, first-ever-receipt on an unborn HEAD,
  a pinned scope-wording check (so a future edit that softens "reviewed by
  anyone" / "ended up in the resulting commit" / "bypassed" fails loudly), a
  clean two-commit run, the `--no-verify` single- and double-bypass cases,
  mid-history adoption, and three "never blocks the commit" cases (git-diff
  failure, ledger-append failure, run from outside a git repo).
* **README.md**: new "Pre-commit hook: receipt the staged diff" section
  documenting what the row proves, what it doesn't, and stating plainly what
  `--no-verify` does to the guarantee.
* Scope not attempted this pass: publishing the hook repo publicly so a real
  `rev: vX.Y.Z` reference resolves for a downstream adopter -- the README
  example uses the existing GitHub remote URL from `pyproject.toml`'s
  `[project.urls]`, unverified against an actual downstream install.

### 2026-09-12: B-007 hostile-corpus check, B-008 skipped (out of repo scope)

* **B-007, confirmed, nothing added:** `arcaeon_ledger.adversarial.HOSTILE_STDIO_LINES`
  covers all five named classes from FINDINGS_INDEX 100D/O4 — deep nesting
  (`deep_nesting_100k`), non-object rows (`top_level_array_empty/number/string/null`),
  lone surrogates (`lone_surrogate_escape`), NUL (`embedded_nul_byte`,
  `escaped_nul_in_method`), and a 10MB line (`ten_mb_line`). `test_mcp_stdio_fuzz.py`
  parametrizes over the whole list against the real MCP server process, so the
  corpus is exercised, not just declared. Nothing missing; no test added.
* **B-008, skipped:** a bundle round-trip test covering all four arcaeon-receipt
  receipt types (cite/call/approval/authorship) needs to know those adapters'
  row shapes, which live in `arcaeon-receipt` — a separate repo this worker's
  scope does not include, even for reading, this cycle (one worker per repo,
  per BATCH_500 §2). `arcaeon-ledger` has zero coupling to `arcaeon_receipt`
  today (`bundle.py` bundles whatever rows a `Ledger` holds; it doesn't import
  or know about receipt shapes), so this test can only be written by whoever
  holds both repos, or after the shapes are handed across in a doc. Reported,
  not attempted.

### 2026-09-12: lane B baseline + mutation-survival count (BATCH_500 B-001/B-002)

No code changes. Recording the numbers the next hardening pass reads before touching anything.

* **B-001 baseline:** `py -m pytest -q` — 465 passed, 0 failed, 494.74s (0:08:14). Green. Safe to build on.
* **B-002 mutation-survival count:** `py -m arcaeon_ledger.mutation_harness` — 16/16 named cases behaved
  (0 survived). Of those 16, only two exercise `witness.py` directly (`truncation-vs-witness`,
  `remint-vs-witness`, both PASS) and **none exercise `bundle.py` at all** — the export-bundle path has
  no mutation coverage in this harness today. Not fixed here; named so the next pass doesn't assume
  coverage that isn't there.

### 2026-09-05: the release gate is vendored, and CI runs it for real

Local commit only; nothing about the shipped package changes.

* **`tools/prepublish_gate.py` is the portable pre-publish gate.** A stdlib-only
  subset of the private gate that has run before every local publish since
  8/15. Five checks, each answering PASS, FAIL or UNVERIFIABLE (exit 0, 1 or 2,
  and "could not check" never reads as a pass): version agreement across
  `pyproject.toml`, `arcaeon_ledger/__init__.py` and a `CHANGELOG.md` heading;
  dist/ holding this version's wheel and sdist with nothing newer from another
  version; the wheel not older than the HEAD commit; the wheel actually
  containing the package with a matching METADATA version; and, on a tag run,
  the tag equal to `v<version>`. Tests in `tools/test_prepublish_gate.py`,
  including two planted-red cases (a wrong version and a stale wheel) that
  were watched failing against a neutered gate before being kept.
* **`.github/workflows/release-gate.yml` job 1 is real.** The sketch that fired
  on the v0.7.5 tag and failed at its own missing script is back on `.yml`
  with that gap closed: it builds dist/ on the runner and runs the vendored
  gate against the tagged commit, and its version step now works for manual
  dispatch as well as tag push. Job 2 (multi-repo smoke) and job 3 (publish)
  stay switched off with their reasons in the header; publishing is still a
  local, gated, human-run act.
* Run locally the same evening against this checkout, the gate reported one
  true finding: the 0.7.5 wheel in dist/ predates the HEAD commit that
  followed the publish. PyPI holds the wheel built from the 0.7.5 commit; the
  later commits are CI and changelog text only. Not rebuilt, on purpose.

### 2026-09-06: the publish gate asks whether the package can answer its own question

* **`tools/prepublish_gate.py` gains a sixth check: `provenance`.** The package
  must be a git repository with at least one commit. This exists because
  `arcaeon-recall` was **published to PyPI from a directory that was not a git
  repository at all** - no history, no diff, no answer to "what changed in
  0.1.1" for anyone who asked. Shipped by the outfit whose entire product line
  is tamper-evident provenance. A sweep of all seventeen `arcaeon-*` directories
  found a second: the GitHub Action, which is worse in kind, because an Action
  is consumed by ref and its version history IS its interface. Both are now
  tracked.
* **Why FAIL and not UNVERIFIABLE, which is the whole point.** The other
  git-dependent checks here degrade to UNVERIFIABLE, correctly: "git is not
  installed" means the instrument could not look. "There is no repository" is a
  different fact - not that the history could not be checked, but that there is
  no history, and the artifact cannot answer the question this company sells the
  answer to. That is a defect in the release, not a gap in the instrument.
  Missing git binary stays UNVERIFIABLE; absent repository fails.
* Four tests pin it, including both halves of that distinction, and they call
  the real function rather than the stub the other tests use - so the check
  cannot quietly rot behind a fixture. The CLI test now asserts six passing
  lines rather than five, which is how a check that stopped being registered
  would surface. 29 gate tests, 425 in the suite.

### 2026-09-06: the evidence bundle's README now says EMPTY about an empty ledger

Package change, unreleased; ships with the next version.

* **`bundle.py`: a zero-row ledger gets its own verdict line.** Since 0.5.8 an
  empty file verifies as `ok=null, verified_scope="empty"`, and `_readme_text`
  had no branch for that: it fell through to the generic "No break was found
  but some rows could not be verified", a sentence written for a bounded scan
  that skipped some rows, printed about a file that has none. A zero-byte log
  is exactly the shape a total wipe leaves behind, and README.txt is the file
  an auditor reads; `verify_report.json` said `rows: 0` honestly while the
  headline understated it as a partial gap. The README now reads
  "VERDICT: EMPTY. This ledger contains zero rows ... indistinguishable from a
  log that was completely wiped." Found by a read-only audit of the last ten
  days of commits, confirmed by building a bundle from an empty file before
  the fix and reading the README. `test_bundle.py` gains the case; it was red
  before the branch and is green after.
* Noted, not changed: the adapter's fallback `verify_seam_log` (used only when
  this package is not installed) counts every unchained row as a break, where
  `verify_file` tolerates pre-adoption rows. That divergence over-reports, it
  never under-reports, and the adapter creates its own seam log fresh, so the
  input rarely exists. Left as is.

## 0.7.5 — 2026-09-05: the MCP server's `strict` flag is a boolean or a refusal, and one hostile character cannot erase a call from its own record

Shipped as 0.7.5 (2026-09-05 evening, board row 211). The fix was found by
an in-process input fuzz
of every shipped Arcaeon MCP tool handler (wrong types, empty and 1 MB
strings, traversal, NUL, lone surrogates, schema-violating JSON), report at
`projects/online_business/audit_arcaeon_mcp_input_fuzz_2026-09-05.md`.

* **`ledger_verify` / `verify_peer_ledger`: `strict` must be a JSON boolean.**
  Both read `bool(args.get("strict"))`, and `bool("false")` is True: a client
  sending `"strict": "false"` (a string; wrong by the schema, but what a
  JSON-in-a-template client produces) got strict mode and an `ok: false`
  "tampered" verdict over an unchained-prefix ledger it had asked to have judged
  leniently. A silent wrong verdict. `_bool_arg` now accepts `true` / `false` /
  absent / `null` and refuses anything else by name. Callers who were sending
  `1` / `0` and getting strict-by-accident now get a tool error; the schema
  said boolean all along.
* **A lone surrogate in the arguments no longer loses the call-record row.**
  `"\ud800"` is legal JSON and reaches the handler as a lone surrogate.
  `_record_call` inlined the arguments verbatim, `Ledger.append` writes strict
  utf-8, the row was never written, and the caller was told "tool ran but its
  call record could not be written". The one thing the record exists for,
  every call leaves a row, was defeatable with one character. The digest
  (over `ensure_ascii` JSON) always stood; now the args body is dropped when it
  cannot be written strictly, the drop is named (`args_omitted`), the error
  text is cleaned the same way, and the row lands.
* **`prove_my_conduct` refuses a batch with a lone-surrogate event before
  writing any of it.** `Ledger.append` refuses per row, so a bad event in
  position 3 of 5 landed the first two and dropped the rest, with only a codec
  error as the reply. A batch is one act: `events[i]` is named, nothing is
  appended.
* **Call-record tool name capped at 256 chars.** The reply already clipped a
  1 MB unknown-tool name to 200 chars; the record wrote all of it.

Regression tests in `test_agent_tools.py` (five new, one parametrized over
six non-boolean values), each shown red against the pre-fix module. Suite
counts before/after in the audit report.

**Addendum, written 2026-09-05 8:55 PM after the wheel was already on PyPI.**
Two more fixes rode this same commit (97e014a) and shipped inside 0.7.5, and
this note did not name them when it was cut. A shipped security fix with no
release line is the wrong kind of quiet, so, late:

* **SECURITY: `bind_artefact` no longer stores a URL's `user:pass@` in the
  record.** `subject.name` and `source_meta.final_url` held the URL verbatim,
  and both are copied byte-for-byte into a ledger row and from there into the
  shareable evidence bundle, so a credentialed fetch URL became a credential
  in the evidence. `_strip_userinfo` scrubs the stored copy; the fetch itself
  still uses the caller's original URL. Tests in `test_artefact.py`. (Found
  by the 2026-09-05 third-verdict code review, board rows 204/205.)
* **`digest_json` / `bind_artefact` raise `ValueError`, not `RecursionError`,
  on a value that nests too deeply to canonicalize** (the write-side twin of
  the `_loads` fix on the read side).
* The companion **arcaeon-adapter** fix from the same review (the spawn-failure
  path wrote the UNREDACTED launch command to stderr, so a credential in argv
  leaked the moment the wrapped server failed to start) is in this tree but
  NOT yet on PyPI: the adapter is still 0.1.3 there. It ships as adapter
  0.1.4 in the next publish window. See `adapter/CHANGELOG.md` Unreleased.

## 0.7.4 — 2026-09-02: the reference witness store refuses a pin whose publisher stamp is from the witness's future

Found by reading the code instead of asserting about it, in a Colony exchange
(deep-seeker, 2026-09-02), and posted before it was fixed. `WitnessStore.record`
wrote two clocks on every pin, `as_of` from the publisher and `received_at` from
the witness, and a comment said the trust surface was precisely that
`received_at` is the witness's. Nothing compared them. A pin whose `as_of`
post-dated the witness's own receipt was admitted, annotated, and served as
verified; the comparison was left to a consumer who would usually not make it.
The refusal machinery (the monotonic guard) already existed and had been
pointed at one invariant, not this one.

- `record()` now refuses, when the store is clock-authoritative (`received_at`
  given), a pin whose `as_of` runs more than `CLOCK_TOLERANCE_S` (300 s,
  declared on the class) AHEAD of `received_at`. Skew is tolerated; a stamp
  from the witness's future is refused in words. An `as_of` the witness cannot
  parse is refused too: an unreadable stamp is not exempt from the comparison.
  With `received_at=None` nothing is compared and behavior is unchanged.
- A refusal leaves a legible mark: one JSON row in a sidecar
  `<store>.refused` (namespace, kind, both stamps, reason). Never in the pin
  chain, which stays pins-only so `latest()`/`history()`/`verify()` keep their
  meaning. The raised `ValueError` is still the gate; the sidecar is the copy a
  stranger can find.
- Honest limit, stated in the code: this catches a stamp from the FUTURE. It
  does not catch a publisher BACKDATING `as_of`; a stamp in the past is
  consistent with any receipt time, and that direction is bounded only
  loosely, by the previous pin.
- The hosted witness (arcaeon-witness) never had this hole in this form: it
  stores only `pinned_at`, its own clock, and does not record the publisher's
  stamp at all.
- Four tests in `test_witness_chain.py`, watched red on 0.7.3 ("DID NOT
  RAISE"): future stamp refused, declared skew tolerated, unparseable stamp
  refused only when clocked, refusal logged legibly with the chain untouched.

Same release, second finding, same day, from our own checker: arcaeon-mcp-vet's
`audit-record` check (OWASP MCP08) graded this server FIRST in the registry
benchmark queue and gave it gate 1 of 4. `prove_my_conduct` appended the
caller's events; nothing recorded the call itself. A ledger server keeping
everyone's record but its own.

- Every `tools/call` now appends one row to a chained sidecar ledger beside
  `--log` (`<log>.calls.jsonl`, `calls_path()`): tool name, the server's own
  timestamp, sha256 of the canonical arguments (always), the arguments inline
  when under 4 KB, outcome, and the error text on a refused or unknown-tool
  call. Written AFTER the tool runs so the row carries the outcome; a crash
  mid-tool loses that one row, and the fix for that is a before-row this does
  not have yet. A separate file so `ledger_verify` over `--log` keeps meaning
  "the operator's records"; a Ledger, not a log, so an edit shows.
- `ledger_verify` replies gain `calls_record`, the verdict over that sidecar,
  so the record set is checkable through the tool a caller already uses. A
  verify cannot see its own row (written after it runs); the reply says 1 on
  a fresh store, and the file says 2 a moment later.
- If the call record cannot be written the reply is an error even though the
  tool ran: a server that acts and cannot say so must not answer green.
- Re-graded with the same checker after the change: gate 4 of 4, and the
  mutant with the record call removed drops back to gate 1, so the grade is
  measuring the record and not the file's vocabulary. Four tests in
  `test_agent_tools.py`, red before `calls_path` existed. 366 → 370.

## 0.7.3 — 2026-09-01: one deeply nested line can no longer crash the verifier or the MCP server

Found from arcaeon-audit's side of the same-day sell-code audit. A line nested
~100k deep (`[[[[...`) overflows the C JSON decoder and escapes as
`RecursionError`, not `ValueError`, so every `except ValueError` in the package
walked past it: `verify_file`, `Ledger.__iter__`, `chain_at`, `_last_chain`
(so `append` after the bomb), and the MCP server's stdin loop all died on one
planted line. A verifier a tamperer can silence with one line is not a
verifier.

- New `_loads()` retypes `RecursionError` to `ValueError` at every parse site
  (five in `__init__`, one in `mcp_server`). Nothing is swallowed: the line is
  counted as `line N: unparseable`, exactly like any other corrupt line, and
  the MCP loop skips it and answers the next call.
- Two planted tests (`test_integrity_regressions.py`), both watched failing on
  0.7.2: verify/iter/chain_at/append over the bomb, and the MCP stdin loop
  answering a `tools/list` that arrives after it. 360 → 362.
- Supersedes 0.7.2, which was staged but never published.

## 0.7.2 — 2026-09-01: verifiers return a verdict, never a crash, on hostile input; no tamper verdict on a ledger that does not exist

Sell-code audit, same day, two more in the same family:
- `mcp_server.py` `prove_my_conduct`: an EMPTY batch on a namespace that had never
  been written ran the verifier over a file that did not exist and returned
  `breaks=1, chain_verified=False` — a tamper verdict on a ledger that does not
  exist. A missing ledger is not a tampered one. It now refuses with a message that
  names the situation and creates nothing. Empty batch on an EXISTING namespace
  (a legitimate "what is my head" read) is unchanged and still covered by its test.
- `witness.py` `latest()`/`history()`: a valid-JSON line that is not an object
  (`[]`, `42`) raised AttributeError; a deeply nested array raised RecursionError.
  A witness log that can be crashed by one appended line is a witness that can be
  silenced by one appended line. Both now skip the line.

Earlier today (folded into this release):

A self-audit found two verify paths that raised on hostile-but-legal input instead
of reporting a break — the one thing this project swears its verifiers never do:
- `witness.py` `_digest_record` re-encoded a pin body without `surrogatepass`, so a
  foreign pin row carrying a lone surrogate (legal JSON) crashed `WitnessStore.verify()`
  and `verify_against_witness()` with UnicodeEncodeError. Fixed to match the chain hasher.
- The adapter's no-library fallback `verify_seam_log` crashed three ways: a non-dict JSON
  line (AttributeError), invalid UTF-8 bytes (UnicodeDecodeError), and a lone-surrogate
  row (UnicodeEncodeError). All three now yield a break verdict, matching `verify_file`.
Both planted-red and mutation-verified.


## 0.7.1 — 2026-08-31: adapter fallback verifier no longer greens an empty seam log

The vendored adapter's FALLBACK verify path (used only when arcaeon-ledger
is not installed — the no-dependency deployment the shim exists to serve)
returned ok=True over an EMPTY seam log, and stopped counting after the
first chain break. Found by our own verdict-field enumeration (2026-08-30);
the fix (tri-state ok, breaks count, verified_scope) had existed in the
standalone arcaeon-adapter repo for four days, unvendored. Vendored forward
tonight; test_adapter_fallback_verify.py pins both behaviors on the forced
fallback path, observed RED on the old code before GREEN on the fix. With
arcaeon-ledger installed the real three-valued verifier was always used and
was never wrong — the blast radius was the ledger-less install, stated
precisely rather than dramatically.

## 2026-08-30: CI and test-only changes (no shipped code; carried in the 0.7.1 tree)

- **CI (2026-08-30):** added Python 3.13 as a third matrix point in
  `.github/workflows/test.yml` (was `["3.9", "3.12"]`, now
  `["3.9", "3.12", "3.13"]`) — buys coverage of the current stable release
  instead of stopping one behind it. The matrix comment's cost note (previously
  "two points … 4-5 point matrix on repos this small") is updated to describe
  three points, honestly, in-file.
- **Test-only fix:** `test_export_bundle_does_not_crash_on_a_corrupted_witness_file`
  imported `arcaeon_audit` unconditionally, which broke CI collection on the
  single-package runner (first red run: ca5c983, 2026-08-30 — arcaeon-audit
  depends on this package, so the dep is circular and can never be declared).
  Now a loud `pytest.importorskip` with the reason in the skip summary; the test
  still runs everywhere the full line is installed. No shipped code changed;
  the published 0.7.0 wheel is unaffected.


## 0.7.0 — 2026-08-30 — three agent-facing MCP tools

The MCP server's first two tools are OPERATOR tools: append a row, verify a file.
They assume the caller owns the file and reads the result itself. These three
assume something else — that the caller is an agent, and that the output is going
somewhere: to a principal who wants proof, or to a peer who wants to be trusted.
Same machinery, shaped for the conversation it actually shows up in. No new
dependencies; the server still speaks JSON-RPC over stdio directly.

**`prove_my_conduct(namespace, events)` → `{rows, head_hash, chain_verified}`.**
An agent logs a batch of what it just did and gets back ONE chain head it can
hand its principal. `head_hash` is read back off the file after the appends, not
computed for the reply, and `chain_verified` is the verifier's own three-valued
verdict over the agent's own log — so an agent whose ledger has been tampered
with cannot hand out a head hash with a green attached to it. That is the failure
this tool exists to sell against, and reporting the appends as successful without
re-verifying would have walked straight into it.

**`verify_peer_ledger(jsonl_text, strict?)` → `{ok, rows, first_break,
declared_breaks}`.** Judge another agent's exported ledger from its TEXT alone —
no access to their machine, no writes on yours (asserted: the caller's own log is
byte-identical afterwards). `first_break` is an INTEGER LINE NUMBER rather than
the library's human string, because a calling agent needs to point at the row,
not parse a sentence; the sentence still rides along in `first_break_detail`. The
text is verified by writing it to a throwaway temp file and calling `verify_file`
— deliberately, because a second verifier that walked the string directly is a
second verifier that can disagree with the first, and the day they disagree is
the day the tool lies.

**`declare_break(namespace, reason)` → `{declared_line, declared_breaks, ...}`.**
The 0.6.0 repair, wrapped for an agent that does not know its own line numbers:
it runs verification, takes the first break the verifier ALREADY found, and pins
that line. If nothing is broken it REFUSES — declaring a break that verification
did not find would put a false sentence into an append-only record, which is
worse than the silence it replaces. It declares one break at a time, so a second
break can never ride in on one sentence, and it never restores a green: the
verdict stays `ok=None` / `bounded_declared_break` with the break counted forever.

**Two honesty rules extended to the new surface.** An export with no parseable
rows now returns `ok=None` / `verified_scope="bounded_empty"` instead of the
vacuous `true` a zero-row scan would otherwise earn — handing a peer a green for
sending nothing is the cheapest possible forgery, and it is the same standing
rule as prechain and declared breaks: only a scan that checked something returns
True. And every new verdict carries `verified_scope`, `prechain` and `declared`
alongside `ok`, so a client that reads `ok` alone still gets null on a bounded
scan rather than a false pass.

**Namespaces are names, not paths.** Agent ledgers live one file per namespace
under `--ns-dir` (default `ledgers/` beside `--log`). A namespace must match
`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; anything path-shaped is REFUSED rather than
sanitized, with a containment check behind the regex as a belt. Silently
rewriting `../etc/passwd` into `etcpasswd` would create a real ledger under a
name the caller never asked for, and the caller would then hand out a head hash
for a file it can no longer find.

`handle(msg, log)` keeps its 0.6.0 two-argument signature; `ns_dir` is an
optional keyword defaulting to `ledgers/` beside the server's log, so existing
call sites and the 0.6.0 integration tests are untouched.

40 new tests in `test_agent_tools.py`, all watched failing before the
implementation existed (40 failed → 40 passed); the existing 309 stayed green.

## 0.6.0 — 2026-08-28 — declare a break instead of hiding it

A hash-chained log written out of band is broken forever, and that is correct:
the break is the true record. Until now the only two things you could do with one
were live with a permanent red or recompute the chain so the file verified again
— and the second is forging, in a package whose entire argument is that a chain
you can silently re-forge is not evidence of anything.

**`declare_break(path, orphan_line, why, resume_prev=...)`** is the third option
and the only sanctioned repair. It APPENDS (never edits) a row naming the break:
which line, the orphan's exact bytes pinned by a full sha256, a human reason, a
date, and the chain value the record resumed from.

**The break stays a break.** `verify()` reports it forever in `declared` (one
sentence per excused break, reason included) and counts it in `declared_breaks`,
which is deliberately NOT folded into `breaks`. What changes is only that a
known, explained, content-pinned break stops masquerading as an unexplained one.

**It cannot mint a green, and that is the load-bearing design decision.** A
declared break yields `ok=None` with `verified_scope="bounded_declared_break"` —
falsy — not `ok=True`. This is the module's own standing rule from 0.5.7 applied
unchanged: only a scan that CHECKED EVERY ROW returns True. An excused row was
not checked; the chain does not link across it, and what stands in for the link
is a human sentence. Declaring converts an unexplained red into a named, bounded
null. That is the whole of what it does, and it is enough. (Where both apply, the
scope reads `bounded_prechain_skipped+declared_break`.)

**A declaration excuses the exact bytes it pinned and nothing else.** Edit the
orphan afterwards and the sha stops matching and the file goes red again, with a
first_break that says so specifically ("a declaration exists but its
orphan_sha256 does not match these bytes") rather than the generic message — the
difference between "nobody explained this" and "somebody explained this and then
the bytes moved" is the entire point of pinning content. A forged
`orphan_sha256`, a declaration pointing at the wrong line, and a declaration with
a blank `why` all excuse nothing. Only two break classes are declarable at all —
an unchained row after the chain began, and a chain mismatch, the two signatures
of an out-of-band append. Unparseable lines, non-object lines, non-string chain
values and unhashable rows are not declarable: those are malformed bytes, not a
recorded event somebody wrote outside the tool, and there is nothing there to
stand behind.

**`strict=True` ignores declarations entirely.** Strict exists for the caller who
wants no tolerance at all — it already refuses the prechain rows non-strict
accepts as legitimate history. A declaration is an unverified human claim, and
honoring an unverified claim is precisely the tolerance strict was asked to drop.
So strict reports a declared break as a break, in `breaks` and `first_break`,
exactly as before this feature existed: **no strict verdict anywhere gets newly
greener because declarations were added.** Strict also refuses the `resume_prev`
pointer that comes with the declaration, not just the excusal — a mode that
declined the exemption while quietly accepting the pointer would be honoring half
of a claim it had just rejected. Strict does still LIST what it refused
(`"declaration present, NOT honored (strict mode)"`), so the gap between the two
modes is visible rather than silent.

**HONEST LIMITS, stated in the function's own docstring and not only here**,
because understating a tool's limits in its own docs is the failure this package
exists to argue against:

- It is a **record device, not a cryptographic one.** Anyone who can write the
  file can write a declaration, so it raises **no** bar against an attacker who
  already has write access. **It defends against forgetting, not against
  tampering.** Every limit below is one more face of this single fact.
- It cannot tell an honest out-of-band append from a malicious one. `why` is an
  unverified human claim; nothing checks it, and nothing can.
- It only declares breaks `verify()` **already found**. It does nothing about a
  break nobody noticed, and gives no help finding one.
- Honoring is decided in a pre-scan, so the declaring row is checked for one
  cheap structural bar (it must carry a `chain`, i.e. have come through
  `append()` — a raw hand-echoed line hands out no exemptions) but NOT for that
  chain verifying. A hand-written declaration with a bogus chain still excuses,
  and is then reported as a break in its own right at its own line.
- `resume_prev` is taken on trust, but a wrong value fails the very next row, so
  it cannot launder a rewritten tail without showing up immediately.

**Mutation-verified**, four mutants, each watched failing before the tests were
kept: dropping the `orphan_sha256` comparison (2 tests red), honoring
declarations under strict (1 red, and it minted `ok=True` on a broken log — the
exact regression property 6 forbids), letting a declared break mint a green
instead of a bounded null (6 red), and dropping the must-be-chained bar on the
declaring row (1 red). `test_declared_breaks.py`, 20 tests.

Also ships the items below, previously staged as 0.5.10 and never published.

## Also in 0.6.0 (was staged as 0.5.10, never published) — a witness never goes backward, and the docs stop contradicting themselves

- **C3 monotonic guard.** `WitnessStore.record()` now refuses a pin whose
  `rows` is below the namespace's history high-water mark, with the same
  semantics the hosted JS service has enforced since 8/14 ("a witness never
  goes backward"). Before this, truncate-then-re-pin sailed through the
  Python reference: the smaller pin became `latest()`, `verify_against_witness`
  read only `latest()`, and the larger old pin — the standing disproof — sat
  unread in `history()`. The bar is the HIGH-WATER mark, not `latest()`, so
  a legacy file already containing a backward pin cannot anchor the guard to
  the low mark. Equal-rows re-pin (the heartbeat) stays allowed. Honest
  limit, unchanged: this stops a backward pin arriving through the API; an
  actor who can rewrite the store file itself is outside it — that
  protection remains the independence of the host. Mutation-verified.
- **Docstring self-contradiction fixed** (found by independent review
  2026-08-24): the module header called a locally-run store "a witness you
  fully control" — the exact opposite of the module's own opening
  definition (a witness is a party OUTSIDE your control), and the exact
  overclaim phrase the 2026-08-23 audit flagged. Local is for development;
  the protection requires a host the logging party cannot reach.
- **README: read the verdict with its qualifiers.** `witness_self_integrity`
  existed in code since 0.5.9 but no consumer-facing doc said to read it. The
  verify example now shows it and states plainly that a bare `"consistent"`
  from a latest-only hosted client is `unestablished`, not `verified`.

## 0.5.9 — the witness store now has a chain of its own

0.5.8 retracted a false claim: the witness store said it was "tamper-evident by
inspection" because it is written append-only, which described how the class writes,
not a property of the file. An edited pin was undetectable. The retraction shipped
before the mechanism did; this is the mechanism.

**Each pin now carries two digests.** `prev` links it to the pin before it, which
catches deletion and reordering. `self` commits it to its own content, which catches
an edit to the LAST pin — the one a verifier actually reads, and the one a pure
back-chain structurally cannot protect because nothing links forward from it. New
`WitnessStore.verify()` recomputes both and names the first break by line.

**That second digest is here because the first draft shipped without it and a
demonstrated-red run caught the gap.** The reviewer's original attack was editing a
single pin; in a one-pin store that pin is the tail, and a back-chain-only version
reported it clean. The test that runs that exact attack is in the suite.

**Legacy files keep working.** Pins written before 0.5.9 have no `prev`; `verify()`
reports them as `unchained` and does not call them broken, because a witness that
rejects its own history the moment it upgrades turns every real pin into a false
alarm. A file with unchained pins and no breaks returns `ok=None` — falsy, scoped,
and honest about what was checked. Same three-valued shape the ledger uses.

**`verify()` returns a verdict whose truthiness follows the verdict.** Writing the
test exposed that it first returned a plain dict, and a non-empty dict is always
truthy, so `if store.verify():` passed over a broken chain — the same container-says-
yes-while-verdict-says-no defect 0.5.8 fixed in `verify_file`. Now `ok is True` is the
only truthy state.

**What this still does not do**, because it is the part that gets overclaimed: it makes
an edit to a stored pin detectable. It does not stop someone with write access from
discarding the file and minting a fresh consistent one, exactly as the ledger's chain
cannot stop a consistent full rewrite. The protection remains substantially the
independence of the host. And `verify_against_witness` NOW consults `store.verify()`:
two guards run before the comparison, so a forged pin file (`witness_broken`) or a
locally broken log (`local_broken`) can no longer be reported consistent. An earlier
draft of this entry described that as a separate release; an auditor caught the
changelog contradicting the code within the same unreleased 0.5.9, and this is the
correction. What the witness still cannot do is stop a full re-mint by someone with
write access, exactly as the ledger chain cannot stop a consistent full rewrite. Do
not read "the witness has a chain" as "the witness gap is closed."

**And `verify_against_witness` now refuses to bless a broken record.** Once both the
log and the pin file had chains of their own, the cross-check could finally consult
them. Before this it compared row counts and chain values without ever asking whether
either side was internally intact — so a forged pin file, or a log broken elsewhere
than the witnessed row, could still come back `consistent`. Two guards run first:
`witness_broken` if the pin file fails its own chain, `local_broken` if the log fails
its own. Both are falsy. Demonstrated red: against the pre-guard code both attacks
returned `consistent`; the tests that assert otherwise fail there and pass here.

Full suite green including 23 new witness-chain tests; `selftest` and
`mutation_harness` unchanged and passing.

## 0.5.8 — four false greens, and a test file that could not detect the drift it was named for

**Upgrade if you are on 0.5.7 or earlier, and upgrade `arcaeon-adapter` alongside it.** Two of the defects below could leave a record silently incomplete while every integrity check still reported green, which is the one failure mode this library exists to prevent.

These were found by a deliberate internal review pointed at proving the library wrong rather than right. Every one was reproduced before it was fixed, and every fix was confirmed to fail against the code it replaces.

**Two things this entry deliberately does not contain.** The step-by-step reproductions are withheld while installs remain on the older version, because a published method for silently removing a row from an audit log is useful to precisely the wrong reader; ask if you have a concrete need for the detail. And the internal review process, tooling and harness are not described, because that is how we work rather than how the product behaves. What you get instead is every defect stated plainly, its consequence, and the limits that remain. We would rather be specific about being wrong than vague about it.

### A file with zero rows is no longer reported as verified

`verify_file` returned `ok=True, verified_scope="full"` over an empty file — a sentence meaning "every row was checked and the chain holds" said about a file containing nothing. Strict mode did the same. Three things downstream believed it: `bool(verify(...))`, `head()`/`publish_head`, and `build_bundle`, whose auditor-facing README printed *"VERDICT: intact. Every row was checked in strict mode and the hash chain holds end to end"* over zero bytes, with the sha256 of the empty string sitting beside it.

Now `ok=None, verified_scope="empty"` — falsy, so `if verify(...)` stops passing, and deliberately still not a red, because an empty log is an absence of evidence rather than evidence of tampering and the two must not print the same.

The README already warned that automation branching on `.ok` "needs to check `first_break`". Our own bundle generator was that automation and did not. **When the library itself cannot follow its own warning, the verdict is wrong, not the reader.**

### `append()` now confirms the row actually landed

It returned a valid chain hash without ever checking that anything was stored, and on Windows there is a class of path that accepts every write and stores nothing. Combined with the defect above, a log could receive writes, keep nothing, and report intact through the CLI, the witness and the evidence bundle. Not a crash — a confident lie, which for this product is the worst failure available.

`append()` now confirms the bytes are present after the write and raises the new **`LedgerWriteError`** if they are not, with a message naming the likely cause. One extra syscall per row, and it is the difference between "the writer believes it wrote" and "the file contains it". A logger that cannot tell those apart is not an audit logger.

### The verifier can no longer be made to crash instead of returning a verdict

Certain legal-JSON rows produced by ordinary cross-language writers could make `verify`, `head` and `build_bundle` fail permanently on a file, while that file remained writable and iterable. That violates an invariant this module states twice about itself: *"one smuggled line turned the verifier into a crash instead of a verdict."* Those rows now come back as `line N: unhashable row (...)`, a break like any other break.

The write path is unchanged and still refuses such a row before any bytes land. The asymmetry is deliberate: a refused write is honest, whereas an accepted write that can never verify is a slow-motion false alarm.

### The chain formula in the README was wrong

It said `chain = sha256(prev_chain + canonical_json(row_without_chain))`. This package defines exactly one canonical JSON — `json-c14n:v1`, compact separators — and **the chain does not use it.** It uses Python's default `", "` / `": "` spacing. Anyone building a cross-language verifier from the README plus the package's only named canonicalization got a mismatch on every honest row. `_chain`'s docstring now states the separators explicitly and says the chain body is its own unversioned rule. No digest or chain value changes; only the documentation was wrong.

### `test_canonicalization_divergence.py` was rewritten, because all five of its tests were decoration

Added the same day as the finding it documents, the file defined a local helper that re-implemented the canonicalization recipe and then asserted things about the copy. When the real `_canon_json` was altered four ways at once — key ordering, separators, ASCII escaping, and NaN acceptance — every test still passed, with NaN quietly digesting under the `v1` label.

Its docstring had claimed "if one starts failing, the canonicalizer drifted". That was unfalsifiable, because the file never touched the canonicalizer. **It was testing a copy of the thing it was guarding, which is the purest form of a check that cannot go red: a green from it only means the copy still agrees with itself.**

Every test now routes through the real `digest_json` / `_canon_json`, the frozen vectors are hardcoded expected strings rather than recomputed (a vector recomputed with the code under test is a mirror, not a vector), and three properties nothing checked before are now covered: compact separators, `ensure_ascii=False`, and the digest label naming its own recipe and version. Eight tests.

### The shipped selftest now tests the product's central claim

`python -m arcaeon_ledger.selftest` is the proof that ships in the package so you can check your own install rather than trusting our CI. With `verify_file` replaced by a stub returning `ok=True` for every file, it printed **ALL CHECKS PASSED** and exited 0. Tamper detection could be deleted entirely and the health check would not notice: its witness branches compare row counts, and its one chain assertion is satisfied by any truthy stub. A user who ran it and saw green had learned nothing about the property they are paying for.

It now plants eight real tampers in real files — in-place edit, deleted row, reordered rows, torn final row, smuggled non-object line, unchained row after the chain began, empty file, and a write that goes nowhere — and requires the **exact** `first_break` string back for each. Demanding the specific line number is the part that cannot be faked by a constant. Plus a green control on an untouched log, so a verifier that is red-by-default fails too. Both directions pinned, which is the only way a check earns the right to be believed.

### Also fixed in `arcaeon-adapter`, same batch

Two defects in the shipped 0.1.0, both breaking the completeness property the adapter exists to provide. A tool call could be missing from the seam log while the chain still verified green — and the party being audited could influence whether its own call appeared. And the wrapped server's command line, which routinely carries live credentials, was written verbatim into the `session_begin` row in the default person-free mode. See that package's changelog; upgrade both together.

**Verified:** 176 fast tests plus the two slow property suites. `selftest` and `mutation_harness` both green.

**Pins deliberately not bumped until the release lands.** Moving a pin ahead of what is published is the defect 0.5.7 records: `>=0.5.7` was declared while PyPI's newest was 0.5.6, and the documented install command failed. Pins move after the upload, not before it.

### Known limits, unchanged or newly named

Stated as limits rather than as attack paths. These are properties the library does not have, not instructions:

- **The witness store carries no chain of its own.** A witness file that an attacker can write to is not evidence; the independence of the host is the whole protection. Its docstring previously claimed it was "tamper-evident by inspection", which was wrong and has been corrected.
- **A witness pin proves nothing about rows appended after it was taken**, and a pin taken over an empty log constrains nothing at all.
- **`verify_against_witness` answers only the witness question.** It can be consistent while the local chain is broken. Check both; they are separate verdicts.
- **A green verdict covers the decoded content of each row, not the exact bytes of the file.** Undecodable byte sequences are normalised on read, so byte-level equality is not what the chain commits to. If you need byte-level custody, hash the file itself alongside this.
- **Concurrency is safe while the lock can be taken.** Contended writers serialise for up to 15 seconds, after which the append proceeds unlocked rather than fail — so a wedged lock, or a platform with no lock primitive, degrades to a single-writer assumption and concurrent appends can fork.
- **`verify_artefact` without `refetch=True` checks a digest for self-consistency, never that the bytes still match.** Only `refetch=True` does that.
- **A consistent full rewrite of an entire log is undetectable by the chain alone.** That is what the external witness is for, and it is the honest boundary of a hash chain.

## 0.5.7 — PUBLISHED to PyPI 2026-08-19 (the version existed for a day before it shipped)

**The defect this closes.** 0.5.7 was written, tested (99 passing), documented in this file, committed and pushed — and never published. Pushing the source read as shipping it. That single gap produced two downstream failures in files that never mention each other:

1. **`pip install arcaeon-adapter[ledger]` failed hard.** The adapter, published the same morning, declares `arcaeon-ledger>=0.5.7`; PyPI's newest was 0.5.6, so the extra could not resolve: *"No matching distribution found for arcaeon-ledger>=0.5.7."* The bare `pip install arcaeon-adapter` worked, which is the command that got verified and reported. Verifying the path you documented is not verifying the paths you published.
2. **`Dockerfile` pinned `==0.5.6`,** so the image shipped a version behind the repo it claims to package. Fixed by publishing 0.5.7, not by editing the number.

**Packaging fix found while checking the artefacts.** The sdist was sweeping in all 15 files of `adapter/`, including its own `pyproject.toml` — a nested project file inside a source distribution confuses build frontends and makes the tarball claim to contain a package it does not install. The wheel was always clean; only the sdist was wrong, which is exactly the kind of thing that survives when you check one artefact and assume the other. Added `[tool.hatch.build.targets.sdist] exclude`, which also dropped the `.hypothesis` test cache. **Sdist went from 318 entries to 26** — now just source, tests, README, CHANGELOG, LICENSE, Dockerfile and server.json.

**Verified after publishing, with the exact command that had failed:** `pip install arcaeon-adapter[ledger]` now resolves to adapter 0.1.0 + ledger 0.5.7 (needed `--no-cache-dir`; pip had cached the pre-publish index while PyPI's simple index already carried both artefacts). The Dockerfile ENTRYPOINT was also exercised directly against the published 0.5.7: `initialize` returns `serverInfo.version 0.5.7` and `tools/list` returns both tools. Docker itself is still unavailable here (`docker`, `go` and `task` all absent, and the WSL image has none either), so the container layer remains untested and the Dockerfile says so.

Written up internally in full. That path is in a private repo, so it is named here only to record that the write-up exists rather than to send you somewhere you cannot go; ask if the detail would be useful.

## 2026-08-19 — `arcaeon-adapter` moves into this repo, and completeness is named as the fifth gap

Repo-level change, no ledger version bump. Two things landed together because they are the same point.

- **The README's honesty list was incomplete.** It named four things a hash chain does not prove and omitted the structural one: *the agent decides what to call `append` on*, so a tamper-evident log of self-reported calls is still self-report. Nothing inside this library can close that, because anything the agent invokes it can decline to invoke. Gap **#5, Completeness**, now says so plainly and points at the closer. A disclaimer list that omits the biggest disclaimer is worse than no list, because it reads as exhaustive.
- **`arcaeon-adapter` now lives at `adapter/`** rather than in its own repository, and is published to PyPI as `arcaeon-adapter` **0.1.0**. It is a stdio proxy that forwards JSON-RPC byte-for-byte between an MCP client and server and writes one hash-chained row per `tools/call` to its own ledger, in a separate OS process the agent does not own, cannot skip, and cannot see. Wrapping it around *this* package's own MCP server produced the number that makes the argument: the server's own diary wrote **0 rows** while the seam log captured **5**.
- **Why the same repo, deliberately:** the adapter is the companion half of one claim rather than a separate product; several distribution directories key off a single repository URL; and splitting related packages across fresh zero-star repos is the exact pattern curated lists auto-reject as coordinated self-promotion (verbatim from `vinta/awesome-python`'s automatic-rejection rules, checked 2026-08-19). Concentrating is worth more than fragmenting when the scarce asset is credibility, not shelf space.

Gates at the time of publish: ledger suite **99 passed**; adapter **65 passed** from its new location; adapter selftest **6/6 with every check observed failing on its own injected defect**. `pip install arcaeon-adapter` verified against live PyPI, not inferred from the upload receipt.

## 0.5.7 (also) — 2026-08-18 — `python -m arcaeon_ledger.bundle`: one-command auditor evidence bundle

Adapter #3 from the 2026-08-18 AI-Act clause-read (founder directive 12396): "we already hold every ingredient; nothing assembles them." Now something does.

- **New module `arcaeon_ledger.bundle`** — `python -m arcaeon_ledger.bundle <ledger.jsonl> [--out DIR|ZIP] [--namespace NS]` assembles a single directory (or `.zip`, chosen by the `--out` suffix) a provider can hand to an auditor or market-surveillance authority: (1) the ledger file **copied byte-verbatim** (the copy's sha256 is recomputed against the source and the build fails rather than ship a divergent copy); (2) `verify_report.json` — the package's own **strict-mode** verify result in full (`ok/verified_scope/rows/chained/prechain/breaks/first_break`) plus the exact `python -m arcaeon_ledger.cli verify --strict <file>` command a stranger re-runs to reproduce it; (3) with `--namespace`, the hosted witness's `/api/latest` response **byte-verbatim** as `witness_latest.json` plus the public GitHub pin-history URL — and without a namespace, or on a failed fetch, a **stated** "no witness evidence included" line in both README and manifest, never silence (a 404/5xx body is kept as evidence with its status: the witness saying "no pin" is itself a finding); (4) a stated **not-included** line for OTS/anchor receipts (this package ships no anchoring tooling; the witness anchors on its own side — deliberately not built here); (5) `MANIFEST.json` — sha256 + byte count of every file, generation timestamp, package version, and the verbatim generation command, so the bundle itself is checkable (the manifest states plainly that it cannot contain its own hash); (6) auditor-facing `README.txt` in plain English — what each file proves, a **what-this-does-NOT-prove** section (truth, completeness, authorship, truncation-without-witness, and no compliance/classification claims), and the legal-context paragraph worded exactly to the clause-read's honest-pitch scope (Art. 12(1), 19(1), 26(6); integrity + provable retention support for the logs those articles make you keep — no "compliant", no "audit-ready").
- **The input ledger is opened read-only and never modified**; the only network call is the optional witness fetch (10 s timeout, injectable for tests). A ledger that verifies RED still bundles — evidence of a broken chain is evidence, and the README states the verdict as BROKEN with the break count. Exit 0 = bundle written; 1 = usage/IO failure. Refuses to write into a non-empty directory or over an existing zip (evidence never clobbered). Stdlib only, like the rest of the package.
- **New test file `test_bundle.py` (19 tests):** dir + zip creation; byte-identical copy with the sha stated in README/manifest; every manifest hash re-verified from disk and a tampered bundle file detected; strict report inclusion on green AND tampered-red ledgers; witness verbatim inclusion with URL-encoded namespace + history URL; no-namespace and simulated-offline fallbacks both stated-not-silent; HTTP-error body kept as evidence; input-never-mutated; README never contains the must-not-say phrases; CLI exit codes. Full suite: 80 → 99 passed.

Defect class identified by ColonistOne (Colony, 2026-08-17 verdict-field audit); found in our own package by the same lens: *a bare boolean whose scope lives in a separate sibling field — the consumer reads the field named after the answer and misses the field that weakens it.* Our verdict-endpoint self-audit confirmed the ledger carried it twice, once at HIGH severity, and this release closes both by making the verdict inseparable from its scope.

- **HIGH — non-strict `verify()` returned `ok=True` while skipping `prechain` rows unverified, and the honest mode was unreachable from both operational surfaces.** The module docstring admitted it plainly: prepend fabricated unchained "legacy" rows in front of a genuine chain and the file verified GREEN — `prechain` carried the count, but the headline `ok`/`__bool__` ignored it, the CLI's documented CI wiring (`return 0 if r.ok else 1`) exited 0 on it, and `strict=True` existed in the library while neither the CLI nor the MCP server could ask for it. Fixes, all three layers:
  - **`VerifyResult.ok` is three-valued (the continuity-0.2.0 `faithful=None` idiom).** `True` = every row verified; **`None` = no break found but prechain rows were skipped unverified — falsy, never a green**; `False` = broken. A consumer that reads only `ok` (or truthiness) now gets a fail-safe non-green on the bounded case instead of a false green. New in-band field **`verified_scope`**: `"full"` | `"bounded_prechain_skipped"` (stamped on failures too — a red over a bounded scan is still a bounded scan). Chosen over keeping `ok` a bool + sibling scope field because the sibling-field shape IS the defect class; chosen over `ok=False`-on-bounded because adoption-on-existing-log is a documented legitimate use and "unverified" is not "broken". Logs with zero prechain rows — every log this library created from genesis — see no behavior change at all.
  - **Distinct CLI exit code: `0` = fully verified, `3` = verified-within-scope (rows skipped; report says how many), `1` = broken/usage.** A CI gate that treats only 0 as green now fails loud on a fabricated prepend. (`2` deliberately avoided — argparse-convention usage-error code.) Documented in `--help` and the README CI snippet.
  - **`--strict` is reachable from the CLI** (`verify --strict <path>` → hard exit 1 on any unchained row) **and from the MCP server** (`ledger_verify` gains an optional `strict` boolean in its input schema, wired through the handler). The MCP tool description no longer overclaims "the whole log" — it states the three-valued verdict and the prechain toleration.
- **MEDIUM — `verify_artefact`: `digest_ok=True` survived a live `refetch:"mismatch"`.** The response's only boolean stayed green while the live-content disagreement rode in a sibling enum. New top-level **`verdict`** tag minted from the pair, so the one-field read is the honest read: a `FAILURE_REASONS` value (offline leg failed) | `"digest_consistent"` (offline leg passed, no live comparison made) | `"live_match"` | `"live_mismatch"` | `"live_unavailable"`. `digest_ok` is now documented as the offline leg only. No field removed or renamed; additive.
- **Regression tests** (`test_integrity_regressions.py` §7): fabricated prepend under non-strict → `ok=None` + falsy + CLI exit 3 + MCP bounded shape (never a clean green); same input under `--strict` / MCP `strict:true` → hard fail; `verify_artefact` refetch mismatch → `verdict="live_mismatch"` with `digest_ok` still honestly `True`, plus every other tag path. The 0.5.4 prepend test and the property suite's legacy-disguise branch updated to pin the new three-valued shape (`ok is not True` on every semantic tamper).
- Compat note: `bool(VerifyResult)` and `ok` are unchanged for all fully-chained logs and all failures. Only the skipped-rows case changes — from the false green to `None`/falsy/exit 3 — which is the fix.

### Also in 0.5.7 — last mutation survivor fenced (2026-08-17, previously unreleased)

Test-only; no product-logic change.

- **New regression test `test_append_after_a_falsy_chain_row_chains_from_genesis` (2 params: `null` / `""`)** in `test_integrity_regressions.py`, killing mutation survivor L5 from the 2026-08-16 mutation pass — the last of the five ledger survivors without a landed test. `_last_chain()`'s `or _GENESIS` fallback repairs a falsy tail `chain` (a hand-edited or rewritten file can end in `"chain": null`); dropping it made the next `append()` compute `_chain(None, body)` — chaining from the literal string `"None"`, silently forking the log from a value no verifier derives — and the whole fast suite stayed green. The test pins the ACTUAL value chained from (must equal `_chain("genesis", body)`), and was kill-proven directly: mutant applied → both params FAIL (`2 failed in 0.45s`); mutant reverted → fast suite `70 passed in 3.52s`.
- **SPDX:** `# SPDX-License-Identifier: MIT` added as the first line of every `.py` file in the repo (14 files), per the license-header pass at repo touch. — U+2028-class sealed-but-unverifiable bug (property-test pass)

Found while adding a `hypothesis`-driven property suite alongside the existing hand-rolled `test_property_ledger.py` fuzzer, prompted by an identical bug found the same night in `arcaeon-continuity`'s probe-file handoff: rows are written with `json.dumps(..., ensure_ascii=False)`, and every read path (`Ledger.__iter__`, `chain_at`, `verify_file`) split the file with `str.splitlines()`.

- **MEDIUM (honesty) — a row whose content contained U+0085 (NEL), U+2028 (LINE SEPARATOR), or U+2029 (PARAGRAPH SEPARATOR) sealed cleanly on `append()` and then could never verify green again.** `json.dumps(ensure_ascii=False)` only escapes the mandatory U+0000–U+001F control range; those three characters (plus the C0 separators `\x0b \x0c \x1c \x1d \x1e`) sit outside it and round-trip **raw** into the JSONL bytes. `str.splitlines()` treats all of them as row boundaries — a real difference from the literal `"\n"` `append()` actually writes as its delimiter — so a row containing one of them was sliced into fragments, each unparseable, and reported as a tamper that never happened. Proof against the pre-fix build: appending `{"note": "contains U+2028 here"}` (a literal LINE SEPARATOR character in the field value) between two ordinary rows produced `verify() = ok=False, rows=2, breaks=3, first_break='line 2: unparseable'` on a completely untampered log. **Fix:** every read path now splits on `"\n"` only — `read_text()`'s universal-newline handling already folds `\r\n`/`\r` to `\n`, so `"\n"` is the writer's one real delimiter either way. Same input after the fix: `ok=True, rows=3, breaks=0`, content round-trips exactly. No format change; `witness.py`'s pin store was never affected (it writes with the `json.dumps` default `ensure_ascii=True`, which already escapes these characters).
- **New: `test_hypothesis_ledger.py`**, a `hypothesis`-driven property suite (separate from the existing seeded `random`-module fuzzer) with named, adversarially-shrunk coverage of: (1) hash-chain integrity — any single row's content mutated, chain left stale, must break `verify()` starting at exactly that row; (2) append-order determinism — replaying an identical record sequence into two independent fresh ledgers must chain identically at every row; (3) the U+2028-class characters specifically, both in combination and pinned one at a time.
- **New regression tests in `test_integrity_regressions.py`**: `test_u2028_class_content_does_not_break_verify` and `test_u2028_class_content_survives_chain_at_and_head`, written failing against the pre-fix build.
- Full suite: **61 → 67 passed** (2 new regression tests + 4 new property tests; no regressions).
- **Docs: `verify()` on missing-vs-empty ledgers, stated plainly.** A never-created path returns `ok=False, first_break="unreadable: ..."`; an explicitly-created zero-byte file returns `ok=True, rows=0`. Confirmed by direct run tonight, not assumed. New README subsection so automation authors branch on `first_break`, not just `ok`, when the two cases need distinguishing. No behavior change.

## 0.5.5 — 2026-08-15 — non-string chain crash (property-fuzzing)

Found by a new property-based / fuzzing pass (`test_property_ledger.py`): thousands of random ledgers built from random content, then random single mutations, asserting the core promise (green on honest, red on tamper, **never crash — always return a verdict**). It surfaced one real bug that the hand-written suite missed.

- **HIGH — a row with a NON-STRING `chain` value crashed `verify()` instead of returning a verdict.** A chain link is a hex string, but nothing enforced it: a row like `{"a":1,"chain":123}` (int, float, bool, list, or dict — all legal JSON, so all arrive from the wire or a corrupt/tampered file) was popped as `claimed`, correctly flagged as a mismatch, and then assigned into `prev`. The **next** row's `_chain(prev, obj)` does `prev + body` — `int + str` — and raised `TypeError` straight out of `verify_file()`. One malformed row turned the verifier into a crash: a denial-of-verdict, the same class the 0.5.3 bare-scalar guard closes for non-object *lines*, but reachable through a non-object *chain field*. Proof against 0.5.4: `{"a":1,"chain":123}` twice → `TypeError: unsupported operand type(s) for +: 'int' and 'str'`. **Fix:** a present-but-non-string `chain` is now a named break (`line N: non-string chain value`), and continuation uses a safe deterministic string so a following honest row (chained from the real hex head) still fails against it — no false green, no cascade. Defense-in-depth: `_chain` now coerces `prev` with `str()` (a no-op on every honest path, where `prev` is always a hex string or `genesis`) so no future route to a non-string `prev` can crash the hash. Same input after the fix: `ok=False, breaks=3, first_break='line 1: non-string chain value'`. All existing tests still pass.
- **New permanent regression suite — `test_property_ledger.py`.** A seeded 5000-ledger property loop (`green` on every honest chain under default AND strict; `red` on every content-changing tamper — chain-edit, byte-flip, non-tail delete, row-swap, mid-line truncation — under strict, with default's one documented legacy-disguise carve-out recorded not asserted-away), plus a 3000-file `verify()`-never-crashes fuzz (bare scalars, `NaN`/`Infinity` literals, binary noise, torn lines, non-string chains, megabyte rows) and a faithful tail-truncation property (green by `verify()`, caught by an external head pin — the documented non-invariant, asserted honestly rather than as a false RED). Scales via `LEDGER_PROP_ITERS`.

## 0.5.3 — 2026-08-14 — chain-integrity fixes (hostile audit)

Found by a deliberately hostile line-by-line audit of the whole package. The first item is the serious one: **a tampered log could pass `verify()`**, with no attacker cleverness required — only an ordinary large row.

- **CRITICAL — a row bigger than the tail read window silently RESET the chain to genesis, detaching every row before it.** `_last_chain()` read a fixed 8 KB tail to find the previous chain value. A final row longer than 8 KB left no parseable line inside that window, so it returned `"genesis"` and the next `append()` started a fresh chain in the middle of the file. Two consequences, the second much worse than the first: (1) honest appends produced `verify() -> ok=False` on an untampered log — the tamper-evidence tool crying wolf about itself; (2) because the chain restarted, **everything before the reset point became detachable** — delete it all and the remainder verifies clean. Proof, run against 0.5.2: a six-row log (payment, payment, fraud_flag, a 9 KB `web.read`, payment, payment), delete the first four rows including the fraud flag, and `verify_file()` returns `ok=True, rows=2, first_break=None`. Rows over 8 KB are completely ordinary — a fetched page, tool stdout, a base64 blob — so this was reachable by waiting, not by attacking. `_last_chain()` now walks backwards a line at a time (doubling blocks, `_line_start_before`) until it has a complete parseable object row, whatever its length; tested at 8 KB, 9 KB, 40 KB, 300 KB and 2 MB.
- **HIGH — a non-object JSON line turned `verify()` into a crash instead of a verdict.** A line containing a bare scalar or array (`123`, `null`, `[1,2]`, `"x"`) reached `obj.pop("chain")` and raised `AttributeError` / `TypeError` straight out of `verify_file()`, `chain_at()` and `Ledger.append()`. One smuggled line meant the verifier could not answer at all — and a caller doing `if log.verify():` got an exception where it expected a verdict. Non-object lines are now a named break, `line N: not a JSON object`, and are consistently NOT counted as rows by `verify_file` or `chain_at` (so witness row-counts stay aligned).
- **HIGH — `verify_artefact()` raised instead of returning a typed failure on type confusion.** Its whole contract is "typed failure, never a silent pass"; a non-string `digest` (int, None, list, bytes), a non-dict artefact, or a non-dict `subject` / `subject.digest` escaped as `AttributeError`/`TypeError`. All of these now return `digest_ok=False, reason="malformed_digest"`.
- **MEDIUM — an up-cased digest read as a different digest.** The hex gate accepts `[0-9a-fA-F]` but the comparisons were case-sensitive, so the same digest in upper case failed `subject_digest_mismatch`, and a re-fetch of byte-identical content reported `"mismatch"`. Hex is case-insensitive by definition; both comparisons now casefold. A genuinely different hex still fails, unchanged.
- **`VerifyResult.breaks`** — total breaks, not just the first. Added because the documented "verification continues from the CLAIMED value so later damage is counted honestly rather than cascading" promise was **invisible**: a cascading verifier produced the identical `first_break` and was indistinguishable from a correct one. One edited row must now measurably be one break.
- **The mutation harness had a hole big enough to hide a 32-bit chain in.** Planting `if claimed[:8] != want[:8]` in `verify_file` — a one-character "optimization" that drops the chain from 128 bits to 32 (birthday-forgeable in ~2^16 work) — left **all twelve cases green**, because every existing mutation changes the row content and therefore the whole hash; none of them could tell a full-width comparison from a prefix one. Four new named cases close that and the rest of this release: `chain-comparison-full-width` (a chain forged in its LAST character only), `damage-counted-without-cascading` (one edit == one break), `large-row-chain-reset` (green across a 40 KB row, red on deleting the history before it), `non-object-row-typed` (a named break, not an exception). Sixteen cases; all four planted defects — truncated compare, cascade, tolerate-unchained, lenient-recipe-version — are now observed red, quoted in the test suite.
- **Honest limits, two named on the write side** (module docstring): rows containing `NaN`/`Infinity` are written as bare non-JSON tokens that round-trip in Python but that a strict RFC 8259 parser in another language rejects — reading an honest log as damaged; and JSON's duplicate-key ambiguity means a hand-written row with a repeated key can read differently to a first-wins parser while the chain stays green over the last-wins parse. `append()` never produces either; both are boundaries a cross-language verifier will meet.

## 0.5.4 — 2026-08-15 — concurrency lock + strict verify + newline heal (second hostile audit)

Carries tonight's newline-corruption fix (below) plus two findings from internal review: a concurrent-append data-loss race and a fabricated-legacy-prepend non-proof.

- **MEDIUM — concurrent `append()` forked the chain and lost rows.** `append()` is a read-modify-write: it reads the previous chain (`_last_chain()`), then writes a row chaining from it. With no lock, two processes both read the same tail, both chain from it, and the chain forks; on Windows the interleaved `"ab"` writes also drop rows outright. Measured against the pre-fix build: 1 seed + 2×20 concurrent appends (41 expected) → `verify() = ok=False, rows=38, chained=38, breaks=17, first_break='line 4: chain mismatch'` — 3 rows lost, 17 forks. It failed RED (never a silent green-tamper), but it both corrupted and lost data. **Fix:** the read-tail + write critical section is now held under a cross-process file lock — `msvcrt.locking` (byte-range) on Windows, `fcntl.flock` on POSIX — on a sidecar `<path>.lock` file, so the lock never touches the emitted bytes. Acquisition is blocking-with-retry (bounded, 15 s), so concurrent writers serialize instead of erroring; a platform with no lock primitive degrades to the single-writer path rather than failing. Same probe after the fix: `ok=True, rows=41, chained=41, breaks=0` — zero lost rows, zero forks. The happy-path emitted format is unchanged. (Same lock pattern as `arcaeon-once`.)
- **MEDIUM (honesty) — `verify(strict=True)` closes the fabricated-legacy-prepend hole, now named as the fourth non-proof.** Rows with no `chain` field are tolerated before the first chained row (adoption-on-existing-log). The hole: PREPEND fabricated unchained "legacy" rows in front of a genuine chain and the file verifies GREEN — they are counted as `prechain` and skipped, and the headline `ok`/`__bool__` ignore the count. Proof: a real 2-row chain with `{"tool":"INJECTED_fake_history","amount":9999}` prepended → default `verify() = ok=True, rows=3, chained=2, prechain=1`. Two fixes, both honesty-contract: (1) a new `strict=True` flag on `verify()` / `verify_file()` treats any unchained row as a break — the same tampered file now returns `ok=False, prechain=1, breaks=1, first_break='line 1: unchained (prechain) row rejected in strict mode'`; (2) "fabricated-legacy-prepend" is now stated as the **fourth** thing the chain does NOT prove, in both the module docstring and the README's "what it doesn't prove" section. The `Ledger` docstring's "atomic appends" is clarified to state the read-tail + write is lock-guarded so concurrent writers serialize.
- **HIGH — `append()` to a file missing its final newline silently GLUED the new row onto the last line, destroying both.** A ledger can lose its trailing `\n` from a torn write (crash mid-append) or any external tool that touches the file. `append()` opened in `"ab"` and wrote `{row}\n` with no separator, so the new row concatenated onto the newline-less last line into one unparseable blob — and `append()` still returned a valid-looking chain hash, so the corruption was silent until the next `verify()`. Proof against the prior build: a one-row valid ledger with its trailing newline stripped, then one `append()`, verified `ok=False, rows=0` — both the old row and the just-written row lost. `append()` now checks the last byte and writes a single leading `\n` only when one is missing, in the same write call; the torn remnant becomes its own flagged line instead of swallowing the new row. A normally-produced ledger always ends in `\n`, so the branch never fires on the happy path and the **emitted format is unchanged** (all 56 tests still pass; the healed case now verifies `ok=True, rows=2`). Found by a second hostile audit, 2026-08-15.
- **`arcaeon-ledger --help` / `-h` now prints usage and exits 0.** It previously exited **1** and dumped the module docstring, because the CLI hand-rolls its argv check (`argv[0] not in ("verify", "append")`) and every flag fell straight into the usage-error branch. A `--help` that exits nonzero is a broken CLI by convention and by CI: a wrapper script or smoke test that runs `--help` to confirm the tool is installed reads the tool as failing. Found by a live-PyPI QA sweep against the published 0.5.2 wheel.
- **`--version` prints `arcaeon-ledger <version>` and exits 0**, sourced from `arcaeon_ledger.__version__` so it can't drift from the package.
- **`verify` and `append` are untouched** — same output, same JSON shape, same exit codes (0 intact / 1 broken / 1 bad usage), verified before-and-after against a scratch install. A bare invocation still prints usage and still exits 1; that one *is* a usage error. Deliberately not an argparse rewrite: argparse would have changed subcommand parsing and error text, and four other packages depend on this CLI behaving exactly as it does.
- **README: corrected the tamper example's line number.** Block 2 claimed `first_break="line 1: chain mismatch"` after editing the amount; the amount lives in row 2, and `verify()` actually reports `line 2: chain mismatch`. Confirmed by running the example. A doc that misreports which row broke undercuts the one thing the library sells — naming the exact line.

## 0.5.2 — 2026-08-14
- **`verify_artefact()` now REFUSES any digest label it cannot reproduce.** Cause, stated plainly: the 0.5.0 mutation harness printed a standing NOTE that a digest claiming `json-c14n:v9` — a recipe version this build has never shipped and cannot recompute — came back `digest_ok=True` with only a warning note appended. The leniency was written for old rows keeping old recipe versions, but a *future* version cannot be an old row, so the effect was that an unchecked digest was reported as verified. That is the exact overclaim this library exists to refuse, and naming it in a NOTE was not the same as fixing it. It is fixed.
- **Typed failures, not substring-matched notes.** `verify_artefact()` returns a new `reason` key: `None` on success, otherwise exactly one of `unknown_algorithm`, `unknown_recipe`, `unknown_recipe_version`, `malformed_digest`, `subject_digest_mismatch` (exported as `FAILURE_REASONS`). Callers branch on the machine value instead of grepping human prose. The `notes` list is unchanged and still carries the readable explanation.
- **Three holes closed, all previously passing:** (1) an unknown recipe *version* of a known recipe passed with a note — now `unknown_recipe_version`; (2) the algorithm field was never checked at all, so `md5:raw-bytes:v1:<hex>` verified green on the strength of a recipe name — now `unknown_algorithm`; (3) the hex body was never shape-checked, so `sha256:raw-bytes:v1:hello` passed when no `subject` block contradicted it — now `malformed_digest` (must be the right length of hex for the named algorithm). An unknown recipe NAME already failed, but untyped; it now carries `unknown_recipe`.
- **A failed digest never reaches the re-fetch stage**, so `refetch` can never report `"match"` for an artefact whose recipe was never verified.
- **Backward compatible for everything actually minted.** `sha256:raw-bytes:v1` and `sha256:json-c14n:v1` — the only labels `bind_artefact` has ever produced — verify exactly as before, `digest_ok=True` with `reason=None`. The append-only recipe promise is kept by a new `SUPPORTED_RECIPE_VERSIONS` registry, deliberately separate from `RECIPES`: `RECIPES` names the version currently *minted*, `SUPPORTED_RECIPE_VERSIONS` names every version this build can still *reproduce*. When a future `json-c14n:v2` ships, v1 stays listed and old rows keep verifying — the leniency's legitimate purpose, kept, without waving through labels that were never real.
- **Observed, not asserted (mutation-harness discipline).** `python -m arcaeon_ledger.selftest` gained a planted-label block: a clean artefact is verified GREEN first, then four plants — unknown recipe name, unknown version, unknown algorithm, malformed hex — must each be seen going red with their SPECIFIC typed reason. The harness gained two named cases, `unknown-recipe-version` and `unknown-algorithm` (12 cases total), and the standing 0.5.0 NOTE is retired because it is now a case observed red rather than a boundary named and left open.
- **The NOTE slot stays occupied, honestly.** It now reports the leniency that remains: an artefact with a well-formed supported digest but no `subject` block passes, because there is no second copy of the hex to disagree with it. `digest_ok` means "reproducible label, self-consistent string" — never "the bytes were re-checked." Only `refetch=True` does that.

## 0.5.1 — 2026-08-14
- **MCP Registry listing marker.** README now carries `mcp-name: io.arcaeon/ledger` (an HTML comment, invisible on PyPI's rendered page) — the ownership proof the official MCP Registry (registry.modelcontextprotocol.io) checks against the PyPI description before accepting the server under the `io.arcaeon` namespace. No code change to the library.
- **MCP server reports its real version.** `initialize` previously answered `serverInfo.version: "0.1.0"` regardless of the installed package; it now reports the package `__version__`. Cosmetic but honest.

## 0.5.0 — 2026-08-14
- **`python -m arcaeon_ledger.mutation_harness` — every claimed check, observed actually failing.** reticuli (Touchstone) set the standard: a check never observed failing is indistinguishable from decoration, so the harness takes each check the verifier claims, introduces the SPECIFIC defect that check exists to catch, and requires the named red — not "some error somewhere." Ten named cases: byte-edit-in-row, row-reorder, mid-row-delete, unchained-row-after-chain-start (each pinned to the exact `first_break` line), truncation-vs-witness and remint-vs-witness (where the chain deliberately stays green — the forgery self-verifies — and the witness must be the one to go red), artefact-digest-mismatch, canonicalization-recipe-drift (a drifted ascii-escaping canonicalizer must fail the frozen golden vector; an unknown recipe label must fail `verify_artefact`), NaN-rejection, and the guard on the guard.
- **No-op guard, and its own selftest.** Per reticuli's second requirement, a mutation that changes nothing must NOT count as caught: every case captures fixture bytes before and after and fails the harness with "mutation did not mutate" if they match — and the `no-op-guard-self-test` case applies an identity mutation and requires the guard itself to trip. Every case also verifies GREEN on the clean fixture first; a harness that only ever sees red proves nothing.
- **Honest boundary, named not papered:** the harness prints a standing NOTE that `verify_artefact` accepts a digest claiming `json-c14n:v9` (a version this build has never shipped) with `digest_ok=True` and only a note — the leniency exists for old rows keeping old versions, but a future version cannot be an old row. The golden vectors, not that check, are the real version-drift guard.
- Meta-test in the suite: blind the chain verifier and the harness must go red naming the case — the harness is itself catchable, by its own standard.

## 0.4.1 — 2026-08-13
- **`python -m arcaeon_ledger.selftest` — golden vectors + the witness planted fixture.** Two launch-thread asks shipped as one runnable command: (1) holocene's recipe-drift question — frozen `json-c14n:v1`/`raw-bytes:v1` digest vectors that any environment must reproduce exactly, so parser/platform drift fails loudly instead of minting well-formed wrong digests; (2) excelsior's witness-failure fixture — three planted branches (truncate-before-witnessed-head → `truncated`, remint-from-genesis → `rewritten`, untouched → `consistent`) run live in a temp dir on every invocation. Exit 0 only when every check passes.
- **Docs: chain hash named `truncated_sha256_128`.** The chain value was documented as `sha256(...)[:32]` without naming its strength; atomic-raven's review nit stands — 128 bits is fine for edit/accident detection, thin against deliberate grinding, and it should never be citable as full SHA-256. README's chain section now names it. (2026-08-13, same night as the 7 reviewer replies.)

## 0.4.0 — 2026-08-13
- **External witness — `WitnessStore` + `publish_head()` / `verify_against_witness()`.** The outside check the chain alone cannot do: no append-only chain catches truncation by itself (chop the tail, the remainder verifies clean — documented since 0.2.1). A witness is a party outside your control that records your head `(rows, chain)` on a cadence; once it holds a pin at time T, a truncated log has fewer rows than the witness saw and a rewritten one has a different chain at the witnessed row. `WitnessStore` is the reference core — file-backed, append-only, holds ONLY fingerprints, never log content ("password nowhere": a breached witness yields hashes useless without the original log). A hosted endpoint is a thin wrapper over exactly this object; run it locally and you have a complete, offline, zero-cost witness.
- **Honest verdicts, stated as verdicts.** `verify_against_witness()` returns `consistent` / `truncated` / `rewritten` / `no_record` — a missing pin is `no_record`, never a false ok, and the result is truthy only on `consistent`. The honest boundary, in the docstring where it belongs: a witness proves no-truncation/no-rewrite only *relative to what it saw, and only as recently as the last pin*. The MAX gap between pins is the real security parameter, not the average — an attacker picks the gap. It says nothing about whether the content was true; that's artefact-binding's job.
- **`chain_at(path, n)`** — the chain value at row n, the primitive the witness comparison stands on; honest `None` past the end of the file.

## 0.3.0 — 2026-08-13
- **Artefact-binding — `bind_artefact()` / `verify_artefact()`.** The move from "tamper-evident diary" toward "evidence layer": bind a re-fetchable fact to a row so a third party can check what the agent actually read, not just that the row wasn't edited. `bind_artefact(source)` accepts bytes, a URL (fetched + hashed with http metadata), a file path, or any JSON value; returns an in-toto-`subject`-shaped dict you chain into a ledger row. Directly answers the launch code-review (a hash chain notarizes a hallucination as faithfully as a fact — bind the source so the claim can be re-checked against it).
- **Self-describing, reproducible digests.** No bare hex ever. Every digest is `sha256:<recipe>:<ver>:<hex>`, carrying its own recipe so a stranger reproduces it from the string alone. Two recipes: `raw-bytes:v1` (opaque bytes as-read) and `json-c14n:v1` (a pinned, documented JSON canonicalization — sorted keys, compact, UTF-8, NaN/Inf rejected). Recipes are frozen and versioned append-only, so a future rule mints `v2` and old rows keep `v1` — a drifted canonicalizer never reads history as tampered. The recipe is deliberately **not** labelled RFC 8785/JCS: a stdlib serialization isn't bit-for-bit JCS on every float edge, and claiming a standard we don't exactly meet is the overclaim this library exists to refuse.
- **Honest verify semantics.** `verify_artefact()` always re-checks the digest string's self-consistency; with `refetch=True` on a URL it re-fetches and reports `match` / `mismatch` / `unavailable` — and a `mismatch` is documented as "content changed OR was tampered, INDETERMINATE," never a bare "tampered." The web mutates; a mismatch is not proof of foul play.
- `digest_bytes()` / `digest_json()` exported for the primitives directly.

## 0.2.1 — 2026-08-13
- **Import name fixed.** The package now imports as `arcaeon_ledger` (matching `pip install arcaeon-ledger`), instead of squatting the generic top-level name `ledger`. Both were flagged repeatedly by reviewers on launch — `pip install arcaeon-ledger; import arcaeon_ledger` now just works, and the CLI/MCP module paths are `arcaeon_ledger.cli` / `arcaeon_ledger.mcp_server`. (Breaking, but done now while adoption is ~0.)
- **`Ledger.head()` + `Head` — external anchoring shipped.** Returns the current chain head + row count + timestamp; `head().as_pin()` gives a one-line, publishable pin. Publishing it somewhere outside your control closes the **truncation gap** (chop the tail and the remainder still verifies — a property of every append-only chain). This was the single most-repeated reviewer critique; the fix is making the anchor a first-class, obvious step rather than a roadmap footnote.
- **Honesty pass on the docs.** README and module docstring now state plainly the three things a hash chain does *not* prove on its own — truncation, truth-of-content, and authorship — each with the concrete way to close it. Being precise about the boundary is the product.

## 0.2.0 — 2026-08-12
- Added `authority()` helper + `append(..., authority=...)`: bind WHO wrote each entry and with what permission (resolved principal, capability version, hashed tool schema, trusted time source). It chains like any field, so editing the writer identity breaks the chain too. Composes tamper-evidence with permission-replay. Shipped same-day in response to community feedback on launch.


## 0.1.0 — 2026-08-12
- Initial release. Zero-dependency tamper-evident, hash-chained action log for AI agents.
- Core library: `Ledger(path).append(record)` and `.verify()`; module `verify_file(path)`.
- Hash chain: `sha256(prev_chain + canonical_json(row_without_chain))[:32]`, genesis-seeded, atomic append (append-binary + flush + fsync).
- CLI: `ledger verify|append` with nonzero exit on a broken chain (CI/pre-ship gate).
- MCP server (`python -m arcaeon_ledger.mcp_server`): drop-in `ledger_append` / `ledger_verify` tools for any MCP client, zero-dependency JSON-RPC over stdio.
- Tested against edit, delete, and reorder tampering, and a full MCP handshake including tamper detection over the wire.
