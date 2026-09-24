## 0.0.17 (unreleased)

* 2026-09-13, **two gates registered on a pattern OUTSIDE this package:
  `seal_chain.publishable_path_key` and `seal_chain.publishable_event`.**
  Both watch `bridge/witness/seal_chain.py`, the fence that decides what may
  leave the house in a PUBLIC chain export, which was widened the same day by
  a recorded decision (`memory/DECISION_BRIEF_export_prefix_2026-09-13.md`,
  Option A; commit f897e1be). 22 chain rows carried a `file` key shaped
  `@liveness/check:<iso>` or `rebreak:<id>:<iso>`, the export refuses at the
  first offender, so all 278 rows were unexportable and smoke item 55 had been
  red for four days; a second blocker was the `event` enum, which 33 rows
  failed on the value `checked`. Registering both here is the condition that
  made the widening reviewable rather than quiet — a fence you widen once and
  then trust is the same fence nobody is watching.
  `seal_chain.publishable_path_key` (allowlist, matcher `_is_path`, 22-entry
  corpus, **11 accept / 11 refuse**) pins the two admitted machine-generated
  shapes — `@liveness/check:<iso>` with its optional `:retraction` suffix, and
  `rebreak:<id>:<iso>` — alongside ordinary paths and a bare digest, and pins
  against them the colon-bearing values that must STAY refused: free prose with
  a colon in it, a URL, `rebreak:` with spaces in the id, a non-timestamp tail,
  a doubled `:retraction`, the un-`@`-prefixed near-miss, a foreign
  `@anything/at/all:` prefix, and two trailing-newline cases (the widening uses
  `\Z` rather than `$` precisely because `$` also matches before a trailing
  newline, and the corpus is what keeps that true).
  `seal_chain.publishable_event` (allowlist, matcher `_is_event`, 11-entry
  corpus, **4 accept / 7 refuse**) pins the closed vocabulary the three real
  writers emit — `genesis` / `changed` / `deleted` / `checked` — and pins as
  refused the shapes a free-text field would sneak in wearing an enum's name:
  `checked` with a trailing space, `CHECKED`, a full retraction sentence
  prefixed `checked:`, a stray `sealed` / `retracted`, an ImportError string,
  and the empty string. Baselines are committed beside the corpora, so any
  later edit that moves either accept set fails CI by naming the exact strings
  that flipped. The `bridge` import is LAZY and inside the matcher: this
  package also ships as a standalone wheel where `bridge` does not exist, and
  `check_gate` returns `no_coverage` before it ever resolves a matcher — so a
  wheel install reports "no corpus" for these two, which is honest, instead of
  exploding at import and taking the other four gates down with it.
* 2026-09-13, **`mcp_vet.gate_drift`: the differential accept-set check for
  pattern gates (task 073).** Spec:
  `memory/FINDING_regex_gate_drift_is_a_real_check_class_2026-09-12.md`. A
  regex gate drifts silently when someone edits the pattern — a DETECTOR
  narrowed (a tightened quantifier) stops catching real positives, an
  ALLOWLIST widened (a new exempt prefix) starts admitting things it used to
  refuse — and no existing unit test sees it, because the defect lives in the
  boundary between named inputs, not at them. `gate_drift.check_gate` runs a
  registered gate's live pattern over a fixed corpus, diffs the accept set
  against a committed baseline (`tests/fixtures/gate_drift/*.baseline.json`,
  sorted-key JSON, one line per string, so a PR that moves a pattern shows the
  flip in the diff), and reports every flipped string by name, in both
  directions, separately. Four real gates registered against the actual code
  this project ships: `badge.banned_verdict_words`, `badge.runtime_claim_words`,
  `checks.secret_stripe_live_key_shape` (the finding's own worked example —
  tightening `{24,}` to `{32,}` silently drops a real 28-character key), and
  `checks.secret_public_prefix_exemption` (the one real allowlist gate here;
  widening `_PUBLIC_PREFIXES` silently un-flags a live-looking secret).
  `test_gate_drift.py` proves both directions can go red: each sabotage is
  applied via `monkeypatch.context()` on the real module attribute, checked
  drift, then checked clean again after the context exits — the sabotage
  target is never a copy, it is `checks._VENDOR_SHAPES` /
  `checks._PUBLIC_PREFIXES` themselves, because the gate specs re-read their
  source module on every call rather than capturing the pattern at import
  time. An empty or missing corpus reports `no_coverage`, never `ok` or "no
  flips"; a corpus with no baseline yet reports `no_baseline`, also never
  `ok` — a check with nothing to compare cannot fail, which the finding calls
  worse than no check, so neither state is allowed to render green.
  **The corpus writer, named rather than assumed:** a developer touching a
  registered pattern writes/extends its corpus and runs
  `python -m mcp_vet.gate_drift --update-baseline` by hand — but the
  reminder that makes that acceptable is real and already scheduled:
  `test_registered_real_gates_are_clean_against_committed_baseline` runs on
  every push/PR touching `projects/mcp_vet/**`
  (`.github/workflows/mcp_vet-tests.yml`), so an edit that moves the accept
  set without updating the baseline fails CI by naming the exact strings that
  flipped. **The honest gap, not shipped quietly:** nothing is scheduled to
  prompt ADDING a wholly new corpus case (a new vendor key format, a newly
  found false positive) — that still depends on a human noticing, same as
  any other fixture gap in this suite. Noted in the module docstring rather
  than pretended solved.
* 2026-09-06, **a refusal says why again: handlers cross the MCP boundary as
  `ToolError`.** From mcp 2.1 the server sorts a tool's exception by TYPE.
  `ToolError` is "a failure you anticipated" and keeps its message; anything
  else is treated as a crash, logged server-side, and the caller is told only
  `Error executing tool <name>`. This server's refusals ARE the product --
  `refused: <path> is outside MCP_VET_SCAN_ROOT` is the sentence a caller needs
  -- and under 2.1 that sentence was being withheld. `build_server` now
  registers every handler through `_anticipated`, which re-types an escaping
  exception as the SDK's `ToolError` with its text intact; the library
  functions still raise their own types, so only the SDK edge changed.
  Found because CI on the mirror went red and stayed red; reproduced in a
  clean venv on mcp 2.1.1 (three tests: both hostile-path refusals and the
  probe backoff control), green there and on 2.0.0 after.
* 2026-09-06, **`pyyaml` added to the `dev` extra.** `test_action.py` parses
  `action.yml` to prove the published GitHub Action and the CLI cannot drift.
  Nothing under `mcp_vet/` imports yaml, so it was never a runtime dependency
  and never got declared -- and CI, which installs only what is declared, died
  at collection with `ModuleNotFoundError: No module named 'yaml'` before a
  single test ran. Test-only dependency, stated as one.
* 2026-09-06, **two environment-dependent tests state their precondition
  instead of asserting into it.** With the yaml collection error cleared, the
  full suite ran on CI for the first time and two more failed, neither a code
  defect: `test_arcaeon_ledger_mcp_server_is_the_reference_record` reads a
  SIBLING checkout (`arcaeon-ledger`) that a single-repo CI
  runner does not have, and `test_fresh_badge_receipt_signer_id_is_in_the_published_key_doc`
  needs the receipt signing key, which lives outside the repo by design (env
  var, else a key file outside the repo), so CI signs with a fresh ephemeral key
  whose DID is correctly absent from the published doc. The first now skips
  only when `CI` is set -- absence stays LOUD on a machine where the sibling
  is supposed to exist, which was the fixture's whole point -- and the second
  skips exactly on "no key present". Neither assertion was weakened.
* 2026-09-06, **the probe fixture models a well-behaved server.** Its
  rate-limited tool raised a bare `RuntimeError`, so on 2.1 the prober saw no
  reason at all and the backoff test failed on a true fact about the world
  rather than a bug. It now raises `ToolError`, which is what a server that
  reports its own 429 does. The opaque-server case is real and worth a check
  of its own someday: a probed server whose errors say nothing gives a client
  nothing to act on. Noted, not built.

* 2026-09-05, **`mcp_vet_audit_verify` goes through the `MCP_VET_SCAN_ROOT`
  fence, and no argument can blow up a reply or an audit row or erase a call
  from the record.** (Ships with the 0.0.17 release; not bumped, not published here.) In-process input fuzz of every shipped Arcaeon MCP tool
  handler; report at `projects/online_business/audit_arcaeon_mcp_input_fuzz_2026-09-05.md`. Three MEDIUM findings, all in `server.py`:
  - **The fence forgot one tool.** `verify_audit_ledger(path)` took a
    caller-named path straight to `verify_file`. With the fence up,
    `mcp_vet_scan` on an outside file was refused and `mcp_vet_audit_verify`
    on the same file returned `rows`, `breaks`, and `first_break: "line N:
    unparseable"`: an existence-and-line-count oracle on any readable file.
    The containment logic is now `_fenced()`, used by `_read` and by
    `verify_audit_ledger`; an out-of-root path raises the same PermissionError
    before any existence check. The server's own audit ledger (under `~` by
    default, so outside any root) is the one admitted exception, because it is
    the file the tool is for. Unfenced behaviour is unchanged.
  - **Amplification.** A 1 MB `path` produced a 1,048,628-byte error reply and
    a 2,097,387-byte audit row (the path echoed in `args.path` AND inside the
    `error` text), per call, unbounded. `PATH_ECHO_MAX = 512` and
    `ERROR_TEXT_MAX = 2000` now clip the echo in every error message, in the
    `ledger` / `detail` fields of the verify reply, and in the row; a clipped
    or cleaned path carries `path_sha256` (over the full text) and `path_len`
    so the row still answers "was it THIS path". After: 587-byte reply,
    1,409-byte max row.
  - **A lone surrogate erased the row.** `"\ud800"` is legal JSON; it reached
    `_record_call` in `args.path` and in `repr(exc)`, `Ledger.append`'s strict
    utf-8 write raised, no row was written, and the caller was told the record
    could not be written. `_clip` now replaces unencodable characters; the row
    lands as `ok: false` with the error, and `mcp_vet_audit_verify` greens over
    it.
  Four regression tests in `test_mcp_server_hostile.py`, each shown red against
  the pre-fix module. Suite counts before/after in the audit report.

* 2026-09-05, **the receipt signer's public key is now published** (board item
  144, pre-staged for the Mon 9/7 6:05 window). The did:key + raw base64
  public key derived from `receipts.load_seed()`'s persistent key (via
  `badge --receipt` on a fixture -- the seed itself was never read or
  printed) now has a second entry, `purpose: "mcp_vet_receipt"`, in
  `projects/arcaeon_site/.well-known/arcaeon/snapshot-signing-keys.json`
  alongside the existing `arcaeon-verified-snapshot` key, byte-identical.
  New test `test_receipt_key_published.py`: a fresh `badge --receipt` run's
  `signer_did` must appear as an active entry in that published file, read
  from the repo path -- a key rotation that forgets to republish the doc now
  fails a test instead of quietly going unnoticed. (Also fixed, in the
  neighboring `arcaeon-verified-snapshot` repo: `load_trusted_keys()` had no
  purpose filter, so this second entry would have been silently trusted as a
  snapshot-signing key too; see that repo's own CHANGELOG.)
* 2026-09-05, **the free CLI badge shipped** (batch-100 item 85, step 2 of 5
  in `PRODUCT_BRIEF_test_honesty_audit_2026-09-04.md`). `mcp-vet badge <path>
  [--receipt]` (`mcp_vet/badge_cli.py`) runs the parity-fixed grader
  (`service.select_files` + `scan_target`, item 146) and prints a Markdown
  badge line (a self-contained `data:image/svg+xml;base64,` embed -- no host,
  no network) plus a JSON block carrying verdict, checks_run, files_scanned,
  `fixture_test_files_pruned` (the count of otherwise-gradeable files the
  parity fix classified as the target's own tests, not its product), the
  `PRODUCT_BRIEF_test_honesty_audit_2026-09-04.md` §8 origin note verbatim,
  and `fixture_coverage` -- mcp-vet's OWN must-hit/must-miss fixture count per
  check, read live off this repo's `test_*.py` files
  (`mcp_vet/fixture_census.py`, new module; `available: false` when a bare
  wheel install ships no test files, never conflated with a genuine zero).
  `NO_GRADEABLE_FILES` renders as a distinct grey badge (`#6b7280`,
  `badge.py`'s new third accent) -- never the clean-slate color, never green,
  never a silent pass; exit code **3**, not 0. `--receipt` signs via
  `receipts.load_seed()` (item 121's persistent-key path) and emits the
  `did:key` signer; without a working key/backend the `receipt` field always
  says `UNSIGNED` and why, never silently and never a bare exception. README
  gained a "Badge" section with the exact command, a real example run, and
  the one sentence the badge is allowed to mean (self-report, not a
  certification). 15 new tests (`test_badge_cli.py`): clean/high/tests-only
  scenarios, the grey accent, the fixture census being non-degenerate across
  all 9 checks, the origin note verbatim, and unsigned-vs-signed receipts.
  Suite 386 -> 401 passed (plus the 1 pre-existing skip). No network, no
  commits, no publishes, no fleet/multi-witness language.

* 2026-09-05, **the `mcp` extra's floor was false at its own floor** (batch-100
  item 42). `mcp = ["mcp>=1.0"]` claimed a range this package cannot run on.
  From the wheels, downloaded and unzipped rather than read about: mcp 1.0.0
  ships neither `mcp/server/fastmcp/` nor a `Client` export, so `server.py`'s
  fallback branch (the one commented "SDK 1.x") cannot import at the declared
  floor; fastmcp appears later in 1.x and is REMOVED in 2.0.0, which is the
  first version carrying `mcp.server.mcpserver` and `mcp.Client`. And
  `test_audit_ledger.py` does `from mcp import Client`, which no 1.x ships, so
  no version in the claimed range has ever run this extra's tests. Now
  `mcp>=2.0.0,<3`, matching `arcaeon` and `arcaeon-ledger-mcp` so the three
  resolve together; `<3` because the 1.x-to-2.x removal is the evidence this
  SDK drops API across a major. The dual-path `try/except` in `server.py` is
  left in place, now unreachable by declaration. Scanner core is still
  stdlib-only and unaffected. Policy:
  `projects/online_business/PIN_POLICY_2026-09-05.md`; enforced by
  `scripts/test_pin_consistency.py`. Suite 377 passed, 1 skipped.


* 2026-09-04, **the two shapes the runtime run proved the rule cannot see are
  now confessed in the grade** (board 118,
  `projects/online_business/mcp_vet_blind_spots_118_2026-09-04.md`). Three of
  the 27 driven findings were NOT-REACHED, in two shapes, and both are
  OVER-reports rather than misses, so both go in `FALSE_RED_EVIDENCE` and both
  ship a fixture that really does draw the wrong finding.
  - **Shadowed site** (`_FR_EXCEPT_SHADOWED`): an `except` returning a success
    shape that sits one layer ABOVE a sibling site swallowing the same failure
    first never executes, and both are counted. `jira/fields.py:879` is
    pre-empted by `:65`, `jira/projects.py:513` by `:375`; monkeypatching the
    inner method to re-raise lit both outer sites, which is what makes them
    shadowed rather than merely quiet. Two findings on one failure path may be
    one defect.
  - **Dead except** (`_FR_EXCEPT_DEAD`): an `except KeyError` over a block whose
    every access is `.get()`-with-default can never run and is reported in bytes
    identical to a live clause. `confluence/comments.py:380` stayed unlit on a
    malformed payload while its subscripting sibling at `:150` lit immediately.
  - **Slip and control, both firing.** Unlike every entry in
    `BLIND_SPOT_EVIDENCE`, where the slip scores 0 and the control proves the 0
    was not vacuous, here BOTH arms fire and only runtime separates them. The
    dead-except pair is the sharpest form: slip and control produce the same
    finding at the same line with the same detail string, and `.get()` versus a
    subscript is the entire diff. Pinned by
    `test_grade_metadata.test_shadowed_and_dead_except_blind_spots_have_slip_and_control`,
    red proved twice (missing confession, then missing coverage key).
  - **One counted line, reported and never subtracted**:
    `except_success_coverage()` gains `dead_keyerror_candidates`, the number of
    `except KeyError` clauses over a try block with no subscript and at least
    one `.get()`-with-default. It is a proxy, not a verdict; a bare `except:`
    does not count. The scan summary prints "N possibly-dead KeyError
    clause(s)".
  - **The rule's behaviour is unchanged.** No finding moved: 376 → 377 tests
    (the one new pinning test), same skip, and what to do about a shadowed site
    is a separate decision taken in daylight, not smuggled in with the
    confession. `BLIND_SPOTS` 29 → 31.

* 2026-09-04 (night), **runtime measurement recorded, no code change.** All 27
  `except-returns-success` findings on the six gate-2 repos were driven with an
  injected dependency failure (HTTP layer replaced before any socket; the
  filesystem server as a child process with `fs.stat` throwing). 24 reachable,
  22 returned a success shape to the caller, 2 raised, 3 not drivable (two
  shadowed by a sibling swallow one layer down, one dead except over `.get()`).
  The 27 findings sit on 18 try blocks. ORIGIN.md and README carry it; per-site
  record in `projects/online_business/mcp_runtime_observability_2026-09-04.json`.

* 2026-09-04, **a finding now points at the defect, not at the door it was
  reached through.** Measured on the gate-2 mcp-atlassian clone right after the
  reachability fix landed: all 26 `except-returns-success` findings carried the
  TOOL HANDLER's `file`/`line` (and not even the reaching one, but the first
  handler in the file, `servers/confluence.py:192`, which is `async def
  search`), while the actual except site was only prose inside `detail` ("in
  get_page_comments() at line 160 of comments.py"). 26 findings, 26 distinct
  sites, every one of them sending a reader to a tool handler with no `except`
  in it.
  - **`file`/`line` are the SITE**: the module the converting body lives in,
    relative to the scan root, and the line of the `return` inside the except
    handler. The return rather than the `except` because it is the line that
    states the lie, and because it is the line gate 2 recorded, so the numbers
    stay comparable to the population this check was measured against. Nine of
    the eleven gate-2 reals recoverable by file:line are now matched by the
    finding's own file:line instead of by reading its prose.
  - **The route moved into structure**: `Finding.via`, a LIST of
    `{"file", "line", "handler"}`, one entry per tool handler that reaches the
    site. Always a list even for one route, so a consumer never branches on the
    count. `detail` still names both ends, with the extra handlers counted
    rather than listed.
  - **One finding per site.** A site several handlers reach is one defect
    carrying several routes: on mcp-atlassian, 26 sites carry 36 routes from 19
    distinct handlers (`jira/client.py:327` alone is reached from six). Coverage
    gains `sites_reported` / `handlers_reaching` and the scan summary prints
    "N site(s) via M handler(s)", so the finding count and the handler count can
    never be read as each other.
  - **The TypeScript half, same rule**: the site is the `catch`'s return line in
    the file the catch actually lives in, and the registered tool handler is the
    `via` entry. A sibling site used to be reported at the graded file's first
    handler line. `file_resolver` now exposes the path it read (`resolve.resolved`)
    so a sibling is named by the file that was opened, never by a guessed
    extension.
  - **No other check's bytes moved.** `via` is omitted from `as_dict()` when
    None, exactly as `gates` is, so every previously emitted grade artifact
    still reproduces key for key. Re-measured: 26 findings before, 26 after, on
    a byte-identical tree digest (`36e716e143f920e0...`); the other five gate-2
    subtrees are unchanged in count and digest.
* 2026-09-04, reachability through an instance a factory returned, plus the two
  measurement defects the reproduction run found. The entry below shipped
  `except-returns-success` and confessed that it had not been run back against
  the six gate-2 repos. It was, the same day, and it reproduced **1 of the 20**
  real findings (`projects/online_business/mcp_vet_rule_reproduction_2026-09-04.md`).
  The miss was one shape, not a shape problem: a tool handler that never names
  the class doing the work, `jira = await get_jira_fetcher(ctx)` followed by
  `jira.get_all_projects(...)`. `_Walker.resolve` saw a dotted expression whose
  head was neither an import nor `self`, so 52 of mcp-atlassian's 53 candidate
  bodies were never entered and five whole modules were reached zero times.
  Four things changed:
  - **A local bound from a call (sync or awaited) now binds to a class** when
    the callee resolves, by import or same-module def, to a function with an
    annotated return type, or to one whose body returns a constructor call, or
    when the callee IS a class. A factory-shaped name (`get_*_fetcher`,
    `*_client`) is only ever used to PROPOSE a class name that must then
    resolve the ordinary way; a name that resolves to nothing binds nothing.
    `local.method()` then opens that class's method (or a direct base's), at the
    same two-hop cap as before. It is opt-in on `_reachable`, so `audit-record`
    keeps the walk it already ships its verdicts on.
  - **Relative imports now anchor at the importing module's own directory.**
    They anchored at the graded file's, so a sibling module's own
    `from .projects import ProjectsMixin` resolved to nothing the moment the
    sibling lived one package over. That was the second lock on the same door.
  - **A receiver we cannot pin is COUNTED, never guessed at**: coverage gains
    `unresolved_instance_calls`, printed on the scan summary line, so the
    not-looked-at is on the face of the report instead of reading as clean.
  - **`@server.call_tool()` / `@app.call_tool()` is a handler root.**
    modelcontextprotocol servers/git and servers/fetch matched neither
    `_TOOL_DECORATORS` nor `_dispatch_handlers`, so both reported ZERO tool
    handlers: a never-asked zero wearing a clean zero's clothes. It is scoped to
    `_audit_roots` and deliberately kept OUT of `_TOOL_DECORATORS`, because
    `check_ssrf` matches a bare `get` as the last component of any dotted call
    and the dispatcher's own `arguments.get("repo_path")` therefore reads as an
    outbound network call: sharing the set turned servers/git from 0 findings
    into 10 false medium reds in one line. Measured, then scoped.
  **The re-measurement.** Same six trees, same entry point: the check fires
  **27 times**, up from 1. Nine of the eleven gate-2 reals recoverable by
  file:line reproduce exactly; 24 of the 53 candidate hits now fire where 0 did.
  All 27 opened by hand: 24 real, 3 false (88.9%). The two named misses are a
  body no handler reaches at all (`jira/worklog.py:182`, whose only caller is
  itself uncalled) and one three hops down behind a property-held adapter
  (`confluence/v2_adapter.py:300`) that the two-hop cap already confesses. The
  three false are one degraded-but-faithful fallback (`jira/client.py:327`
  returns the input text wrapped in a valid document) and two fail-closed guards
  whose polarity is stated in a `logger.warning` f-string rather than a comment,
  which is where exclusion (b) cannot read. Recorded, not tuned away: widening
  the polarity heuristic to hit a number I had already measured would be the
  measurement not counting.
  **Also fixed, both found while measuring.** `scan` routed every file to the
  Python front end, so `python -m mcp_vet scan index.ts` printed a false
  "could not parse: closing parenthesis" and ran no TypeScript check at all;
  `scan_file` now routes by extension the way `grade_source` already did. And
  the coverage line was Python-only, on a tool whose only real hit on this
  population came from the TypeScript side: `ts_checks.ts_except_success_coverage`
  reports handler roots, bodies walked, catch clauses examined and files that
  would not parse. supabase-mcp is the case it exists for: 24 registered
  handlers, 29 bodies walked, ZERO catch clauses reached. That zero means "not
  looked at" and the tool can finally say so.
  One new confession in `grade.BLIND_SPOTS` with its slip and control, for the
  part that stays open: the instance must be held in a NAMED LOCAL bound from a
  call whose definition the scan can open. `get_fetcher().method()` chained in
  one expression, `self.api.method()`, and a factory defined outside the scanned
  tree all bind nothing.
  Tests: 10 added to `test_except_returns_success.py` (40 total), including a
  four-file fixture of the mcp-atlassian layering, because the shape only exists
  across a file boundary. Every new branch was disabled in turn and the tests
  watched go red. Suite: 371 passed, 1 skipped.
  Report: `projects/online_business/mcp_vet_reachability_fix_2026-09-04.md`.

* 2026-09-04, `except-returns-success`: a ninth check class, on BOTH front ends.
  An exception handler on a tool-reachable path that returns a success-shaped
  value (`[]`, `{}`, `""`, `True`, a None-free dict/list literal, or a call
  building one) with no error marker in it. The failure is serialised into the
  tool result and the agent cannot tell it from a real answer.
  **Why this one and not the family it came from.** Gate 2 (2026-09-04) ran the
  whole "vacuous pass" rule family against six real MCP servers, 66,909
  non-test lines, and opened all 196 hits by hand. The family scored 21 real of
  196 (10.7%) and FAILED its 30% gate. Exactly one idiom cleared the gate on its
  own: this one, 20 real of 57 opened, 35.1% (the IDIOM's number from the
  scratch harness; the shipped check re-run the same day reproduced 1 of the 20,
  see ORIGIN.md "Reproduction"; reachability gaps are open work). The other six scored 1 real hit
  across 139 opened (except-swallow 1/101, all-empty 0/22, default-true 0/8,
  the lint's own except-true 0/3, absence-pass 0/3, catch-null 0/2) and are NOT
  shipped, because noise on a stranger's file is the one cost this project
  cannot pay. Shipping the whole family because the family was the idea would
  have been the measurement not counting.
  The worst real case, and the reason reachability is part of the rule rather
  than a later refinement: mcp-atlassian `jira/projects.py:49` catches bare
  Exception, logs, and returns `[]`; the tool wrapper at
  `servers/jira.py:3390` has a careful error path that never fires because the
  fetcher one layer down already converted the failure into an answer, and the
  agent receives `json.dumps([])` as "there are no projects." The same `return
  []` in a helper no tool reaches is a contract, not a lie, so the check walks
  out from the tool handlers through the same `_Walker`/`_reachable` the
  audit-record check uses, and never asks the question of an unreached body.
  Three exclusions, each one a FALSE hit the gate paid for by hand: (a) the
  literal carries its own error marker (`error`, `isError`, `errors`,
  `success: False`, `ok: False`) - five hits in `jira/attachments.py` were
  `return {"success": False, "error": msg}`, the exact opposite of the defect;
  (b) the polarity is documented (heuristic ported from
  `scripts/vacuous_pass_lint.py`, which cannot be imported by a shipped wheel) -
  all three of the lint's own hits were documented fail-closed `return True`s
  where True is the SAFE answer; (c) the handler re-raises or hands back the
  caught exception. A `None`/`undefined` inside the literal is a modelled third
  state (supabase-mcp `api-platform.ts:381`) and is left alone.
  TS side is tree-sitter, not the brace-matching regex the gate's scratch
  harness used: this module has parsed TypeScript with tree-sitter since
  0.0.17, and a second weaker parser beside it would mean two parsers
  disagreeing inside one file. Real TS case modelled: `src/filesystem/index.ts:500`,
  a failed `stat` reported as a zero-byte file dated 1970 and folded into the
  "Combined size" total.
  Coverage is reported, not implied: `checks.except_success_coverage()` counts
  tool handlers, reachable bodies, except handlers read and files that would not
  parse, and `python -m mcp_vet scan` prints them as one more line on the
  summary it already writes. Without it, "0 findings" cannot be told apart from
  "0 bodies looked at", which is the same third verdict this check is about.
  Two new confessions in `grade.BLIND_SPOTS`, each with a slip fixture that
  scores zero and a minimally different control that fires: the success shape
  must be a LITERAL on the return (`out = []; return out` is invisible), and the
  walk from handler to converting body is capped at two call hops and crosses
  into a sibling module only on a directory scan.
  Tests: `test_except_returns_success.py` (30), a must-hit and a must-miss for
  every branch with a minimally different control on every must-miss, plus a
  test that pins the six idioms gate 2 said to leave alone. Origin and the
  measurement that gated it: `ORIGIN.md`.
  Two existing statements moved because this made them false, both noted here so
  the edit is not silent: `verify_page.CANNOT_PROVE` said "One check on
  TypeScript" and now says two, and the TS tests' hand-kept `["audit-record"]`
  literals now read `[name for name, _ in tc.TS_CHECKS]` - a second copy of a
  check list is exactly the drift the registry exists to prevent.

* 2026-09-03, X35 + the read fence: `MCP_VET_SCAN_ROOT` confines every file
  read to a subtree, implemented at `_read` because that is the single
  chokepoint all entry points share. Without it this server reads ANY absolute
  path a connected agent hands it. A RELATIVE path resolves against the root
  rather than the process cwd (otherwise `chdir` is an escape hatch and the
  fence only holds for callers already behaving); `../` and symlinks normalise
  before an `is_relative_to` containment test rather than a string prefix, so
  `/rootless` cannot slip past a `/root` fence; and an out-of-root path is
  refused IDENTICALLY whether or not the file exists, because a distinct "not
  found" answers questions about the filesystem outside the fence one bit at a
  time. Opt-in, so existing callers stay byte-identical - a security control
  that arrives as a mystery breakage gets switched off rather than understood.
* 2026-09-03, and it is the reason the fence exists: `test_mcp_server_hostile.py`
  imported `SCAN_ROOT_ENV` from `mcp_vet.server`, which did not exist, so pytest
  ABORTED DURING COLLECTION and nothing in the suite ran. The file had been
  committed on the strength of a 298-passed run that predated it. **A collection
  error is worse than a failing test: a failure reports, a collection error
  hides every other result.** The test was not junk either - it was a
  specification for a fence nobody had built, so it got implemented rather than
  deleted.
* 2026-09-03, X35: `_BS_HOSTILE_INPUT` states the confession this grader owed -
  it grades servers on hostile-input handling and its own was unfenced.


* 2026-09-02, M35: `Grade` carries two DISTINCT record fields, `record_static`
  (what the scanner inferred from bytes: asked, presence, the four MCP08
  gates, gates_met) and `record_dynamic` (None unless a runner wrote it via
  `grade.dynamic_record()`, the only constructor). Grade schema 1 -> 2.
  `badge.py` never merges them: two rows labelled `record`, the static line is
  copy-tested against runtime vocabulary (observed / confirmed / runner /
  launched / executed) and a badge from a static-only grade always draws
  "runtime: not confirmed (no runner ran)". A `TargetGrade` (service.py,
  predates the fields) draws the honest empties, not invented values.
  Tests: `test_record_evidence.py` (11).
* 2026-09-02, M37: the badge says what the mark IS. Footer is two lines from
  `badge.FOOTER_LINE_1/2`, leading with the exact phrase
  `badge.RECEIPTED_NOT_REVIEWED` = "receipted, not reviewed": "this mark
  records which checks ran on which bytes. No human reviewed this server. Not
  a safety certification. Verify the receipt." The SVG is copy-tested against
  the phrase and the two lines verbatim.
* 2026-09-02, M38: `mcp_vet/verify_page.py`, the page a stranger lands on from
  the badge. States four things the badge cannot prove (static read only, one
  check on TypeScript, blind spots listed, no runtime evidence) and renders
  the blind-spot list FROM `grade.BLIND_SPOTS` at render time between
  marker comments; `test_verify_page.py` asserts word-for-word equality. No
  verify URL shape exists yet (`receipts.verify_url` is empty until R15), so
  the module returns self-contained HTML and the memo says the URL is unset.
* 2026-09-02, M39: `mcp_vet/instrument.py` `timed_scan_target()` wraps
  `service.scan_target` (unchanged) with a stopwatch plus bytes read / tree
  bytes; `scripts/cost_per_check.py` runs it over our five working trees and
  `tests/fixtures`. `design/COST_PER_CHECK.md`: warm median 0.311 s, p95
  1.111 s (n=42); cold median 0.499 s (n=6); bytes read median 83 KB. Real
  run, 2026-09-02 16:29 PDT, numbers not estimated.
* 2026-09-02, M34: `scripts/own_five_probe.py` (NOT under bench) launches
  OUR OWN five servers only, from their working trees, stdio, 30 s budget,
  no network; sends initialize + tools/list + one tools/call and reads each
  server's call record back from a scratch path. Result 5/5 launched
  headless, 5/5 static 4/4 gates, 5/5 dynamic row observed, 5/5 agree
  (working tree, unpublished). Table in `design/SANDBOX_RUNNER.md` appendix.
* 2026-09-02, M33: `design/SANDBOX_RUNNER.md`. Isolation options against
  this box (bare subprocess: fine for ours, not for strangers; WSL2 container
  at zero dollars; hosted microVM), network default none, 30 s timeout, cost
  in seconds / bytes / dollars (E2B list price cited, about $0.002 to $0.006
  per server), and what a dynamic confirmation changes (one field, one row,
  one sample; the verdict does not move). Decides nothing about spend; ends
  with the one-sentence question for Daniel.
* 2026-09-02, M1/M2/M4/M5/M6/M7 (Python): the audit-record reachability walk
  follows the honest recording shapes instead of same-file calls only. Before
  this a server whose record sat one import, one decorator, one `self.` or one
  middleware registration away scored gate 0, the false red the whole line
  cannot afford. The walk (`checks._Walker`, `_reachable`, `_middleware_roots`)
  now resolves: a same-package import of the recorder, relative
  (`from .audit import record`) or absolute (`from pkg.audit import record`,
  `import pkg.audit as au; au.record(...)`), anchored on the nearest ancestor
  directory named like the first segment (four levels up at most); bare and
  factory-call decorators on the handler (`@audited`, `@with_ledger("add")`)
  whose body records; `self.<name>(...)` / `cls.<name>(...)` to a method of the
  handler's own class or a DIRECT base, same file or sibling module (one level
  of inheritance, no deeper); `with recorder(...):` context expressions as call
  sites; and construction-time middleware, both registered
  (`server.middleware(...)`, `add_middleware`, `use`, a `middleware=` keyword,
  a `@server.middleware` decorator; a passed class contributes all its methods)
  and wrap-the-dispatcher (`server.call_tool = wrap(server.call_tool)`).
  `max_depth=2` is unchanged. Precision note: `self.`/`cls.` lookups are now
  CLASS scoped; the old file-wide short-name fallback used to resolve
  `self._log` to any `_log` in the file, which meant deleting the base class
  did not change the grade. It does now.
  Plumbing: `grade_source(..., package_dir=None)` and
  `scan_source_ex(..., package_dir=None)`; only checks that declare
  `package_dir` receive it. `service.scan_target` passes each Python file its
  directory when the target is a DIRECTORY, never for a file target: a
  single-file receipt pins one sha256 and its grade may not depend on siblings
  it does not pin, so `verify()` stays reproducible. The tamper-evidence and
  reconstructability gates now read the sibling modules the walk actually
  opened, so a two-file server can reach gate 4. Single-file mode stays blind
  to imported recorders and SAYS SO (`_FR_MCP08_SINGLE_FILE`).
  Honesty: the old one-sentence middleware confession is replaced by five, one
  per shape the walk still cannot follow, listed in
  `grade.MCP08_REACH_BLIND_SPOTS` with a firing fixture each in
  `FALSE_RED_EVIDENCE`: single-file mode, a recorder from a package outside the
  tree, a grandparent-class recorder (one-level limit), a Server subclass
  overriding `call_tool`, and a decorator bound by assignment from a factory.
  Fixtures: `tests/fixtures/recorders/` holds one per shape (two-file shapes as
  packages), three genuine gate-0 servers (`gate0_no_record`, `gate0_print_only`,
  `gate0_lookalikes`: a `@timed` decorator, a `quiet()` context, a
  `self._validate` call, a `Cors()` middleware and a retrying `call_tool`
  wrapper that record nothing), and one `blind_*` fixture per confessed
  sentence. `test_recorder_shapes.py` is table driven: every fixed shape scores
  4 clean and 0 after its mutation (delete the import, the decorator, the
  call, the base class, the registration); the blind-spot count must equal the
  `blind_*` fixture count; each blind fixture must still score 0; and
  `scan_target` on `m1_relative_import/` is clean while the same `server.py`
  as a file target is high. Not done here: `bench/grade_sample.py` and
  `grade_own.py` still call `grade_source` per file without `package_dir`, so
  the bench still sees single-file numbers for import-shaped recorders; both
  could pass the file's directory (the bench is owned elsewhere).
* 2026-09-02, M13: extension routing lives in ONE place. `grade_source` decides
  by extension (`ts_checks.is_ts_path`); `service.scan_target` now walks `.py`
  AND `.ts/.tsx/.js/.mjs/.cjs` (`_gradeable`) and never routes itself. A TS
  tree grades with `checks_run == ["audit-record"]`; a mixed py + ts tree reports
  the intersection (`["audit-record"]`) and never implies the Python battery
  ran on the TS. `files_skipped` no longer lists TS files as skipped.
  Tests: `test_m13_*` in `test_ts_recorder_reach.py`. `bench/grade_sample.py`
  keeps its own walk for now (owned elsewhere); it could switch to
  `scan_target` later.
* 2026-09-02, M15: the TS walk follows a RELATIVE IMPORT to the recorder.
  `import { record } from "./audit"` / `"./audit.js"` (named, default,
  namespace, and `require` destructuring) resolves to the sibling file when
  `scan_target` hands `grade_source` a tree-scoped resolver
  (`ts_checks.file_resolver`; refuses paths outside the tree; `.js` specifier
  finds `.ts` per TS convention). Siblings are parsed once and their own imports
  are not followed; the tamper-evidence and reconstructability gates read
  sibling bodies too. A single-string grade (no resolver) still reports the
  finding, so `verify()` stays self-contained. Fixture:
  `tests/fixtures/ts/import_recorder/` (server.ts + audit.ts) is clean as a
  tree and red alone; deleting the import or the call goes red
  (`test_m15_*`).
* 2026-09-02, M16: wrapper and decorator recorders. `server.tool(name, schema,
  withAudit(handler))` and `const h = withAudit(fn)` unwrap the call and follow
  the wrapper's body; NestJS / mcp-nest `@Tool(...)` methods are handler roots
  and a sibling `@Audited()` decorator factory's returned function is walked.
  Fixtures: `tests/fixtures/ts/wrapper_recorder/`,
  `tests/fixtures/ts/decorator_recorder/`; removing the wrapper or the
  `@Audited()` line goes red (`test_m16_*`).
* 2026-09-02, M17: honesty without the `[ts]` extra is now a test, not a
  promise. With `tree_sitter` / `tree_sitter_typescript` made unimportable
  inside the test (sys.modules poisoning + reload; nothing uninstalled), a `.ts`
  file grades `checks_run == []`, verdict equal to `grade._UNPARSEABLE`
  ("unparseable, 0 checks ran"; not a pass verdict), and the parse finding names `arcaeon-mcp-vet[ts]`; same
  through `scan_target`. `pyproject.toml`'s `[ts]` extra is asserted to be
  exactly `tree-sitter>=0.25` + `tree-sitter-typescript>=0.23`
  (`test_m17_*`).
* 2026-09-02, M14 (memo only): `design/TS_SECOND_CHECK.md` compares
  `secret-in-code` vs `unsafe-exec` as the second tree-sitter port. Decision:
  `secret-in-code` first (about 80 percent ports unchanged, false-positive
  story already paid for); `unsafe-exec` held until it ships with a
  handler-parameter taint gate. Nothing implemented.
* 2026-09-02, bench M23: summary JSON is now schema 1 (`bench/summary_schema.py`):
  `schema`, snapshot sha256, seed expression, mcp_vet_version, plan path,
  buckets, gate histogram, `exclusions`, `battery_digest`, `no_handler_found_split`
  all REQUIRED; a summary missing any one is refused by the grader and the
  renderer (`test_summary_missing_any_required_key_is_rejected`, one case per key).
  The 2026-09-02 summary was backfilled by adding keys only; every pre-existing
  key is byte-identical (the old file is a byte prefix of the new one). Its
  `battery_digest` reads `unrecorded:run-predates-schema-1` because the battery
  bytes at 21:42Z were not recorded; the working-tree digest at backfill time
  sits beside it, labelled as not the tree that graded.
* 2026-09-02, bench M24-M28 + M32: `bench/render_report.py` renders the
  publishable table read-only from a summary. Header row = sha, seed, version,
  battery digest. Raises without `exclusions`; raises without the own-five
  block. Opens with our five at their PUBLISHED gates (ledger 1; distill, once,
  continuity, connector 0) outside every denominator; no line implies our
  servers pass our own checker (asserted by regex in
  `test_report_opens_with_ours_at_published_gates_outside_denominator`). Every
  pass rate is printed next to its exclusion list (headline, gate ladder, and
  language table each carry "Excludes: ours 5; no-handler-found 49; ...").
  Language rows carry `checks_run` (Python 8 checks, TS/JS 1) and are never
  summed or averaged. The static-read blind-spot paragraph is inlined verbatim
  from PLAN.md with a copy test. Output: `bench/results/2026-09-02T2142Z_report.md`,
  asserted equal to `render(summary)` on disk.
* 2026-09-02, bench M31: headline gate-0 share 30/33 (90.9%) now carries a
  95% Wilson score interval, 76.4% to 96.9% (`summary_schema.wilson_interval`,
  `test_wilson_interval_on_30_of_33`). Wilson over the normal approximation
  because the share is near the edge, where the normal interval runs past 100%.
* 2026-09-02, bench M20: `no-handler-found` splits into `unsupported-language`
  (Go/Rust/Java/C# markers, or no .py/.ts at all), `monorepo-miss` (a
  package.json/pyproject.toml in a directory the walk did not read), and
  `no-handler`; post-hoc classifier `grade_sample.classify_no_handler` over the
  row's `repo_markers` / `manifest_dirs` / `scanned_dirs`. The historical 49
  rows predate those fields and CANNOT be split: reported as
  `unclassified:pre-M20-row` = 49, the three reasons 0, sum = 49
  (`test_historical_49_are_unclassified_and_the_split_sums`).
* 2026-09-02, bench M19: future runs grade every manifest directory the
  `repo_subfolder` walk missed before a row may say no-handler-found
  (`grade_checkout`, rescue marked `found_via: manifest-scan`); proven on a
  temp monorepo where the registry subfolder points at `docs/` and the server
  lives in `packages/server/` (`test_monorepo_subfolder_miss_is_rescued_by_manifest_scan`).
  The frozen 100 rows are untouched.
* 2026-09-02, bench M18: PLAN.md addendum inventories the handler-registration
  markers of the Go (`mcp.AddTool`, mcp-go `s.AddTool`), Rust (rmcp `#[tool]`,
  `#[tool_router]`, `#[tool_handler]`), Java (`SyncToolSpecification` +
  `addTool`, `.toolCall`), and C# (`[McpServerToolType]`, `[McpServerTool]`,
  `WithToolsFromAssembly`) SDKs, with sources. Not added to the scanner.
* 2026-09-02, bench M22: `grade_sample.bucket_counts` puts every active server
  in exactly one of four buckets, recomputes the label from the row's fields,
  and raises `BucketError` on an unknown or contradicted label; buckets must
  sum to the active count (`test_planted_unbucketed_row_fails_the_denominator`,
  `test_planted_mislabelled_row_fails_the_denominator`).
* 2026-09-02, bench M30: results are append-only. `append_row` is the only
  writer; an identical row (modulo wall-clock `seconds`) is a no-op, a
  differing row for the same name raises `ResultConflict`; a results file
  already holding a conflicting duplicate refuses to load
  (`test_results_append_only_identical_noop_differing_raises`).
* 2026-09-02, bench M29: `bench/REPRODUCE.md`, the exact commands from
  snapshot sha to table; `test_same_snapshot_same_sample_order_twice` asserts
  seed determinism on a synthetic snapshot.
* Tests: 42 new in `test_bench.py`, none touch the registry or the 36 MB
  snapshot. 231 total pass.

## 0.0.16 — TypeScript front end for `audit-record` + the registry benchmark (2026-09-02, unreleased)

**Why.** A 300-row smoke of the official registry showed npm packages
outnumbering PyPI 32:1. A Python-only scanner grading "the registry" grades a
rounding error of it. Full snapshot the same afternoon: 26,197 active servers
(88,636 version rows), npm 8,063 vs PyPI 3,515. The "18,800 servers" quoted
in our own docs for a week counted neither; corrected in three files.

**What.**
* `mcp_vet/ts_checks.py`: tree-sitter front end running ONE check,
  `audit-record`, over `.ts/.tsx/.js/.mjs/.cjs`. Same four gates, same
  `Finding` shape, same field vocabulary (imported from `checks.py`, one list).
  Handler shapes: `server.tool()`, `registerTool()`,
  `setRequestHandler(CallToolRequestSchema, …)`, fastmcp-ts `addTool({execute})`;
  handler passed by name is followed; reachability depth 2, same cap.
  Optional extra `pip install arcaeon-mcp-vet[ts]`; without it a TS file grades
  "unparseable — 0 checks ran", never clean. `checks_run` on a TS grade is
  `["audit-record"]` and nothing more.
* `grade_source` routes by path. `service.py`'s tree walk stays `.py`-only for
  now (benchmark walks TS trees itself); wiring it is the next item.
* `checks.audit_record_applies(source)` / `ts_checks.audit_record_applies`:
  did the check ASK this file (handlers + entrypoint)? Needed because an empty
  finding list means "all gates met" for a server file and "not applicable" for
  a test file, and the benchmark's very first run scored `arcaeon_connector` by
  its test file.
* `bench/`: `registry_scrape.py` (content-addressed snapshot, every row
  bucketed, nothing dropped from the denominator), `PLAN.md` (sampling plan,
  fixed before grading), `grade_sample.py` (seeded sample of 100 from
  `gradable:repo`, shallow clone, best-file gate 0–4, resumable).
* 18 new tests (`test_ts_audit_record.py`), incl. a mutation (delete the audit
  line, presence flips) and the not-installed path. 189 total pass.

**Our own five, graded first with the same code (E102):** arcaeon-ledger gate 1
(presence only: the ledger appends the caller's events, not a record of its own
tool call); distill, once, continuity, connector gate 0 (no call record on any
tool path). Fix owed before any distribution is published.

**Benchmark result (2026-09-02, 100/100, `bench/results/2026-09-02T2142Z_*`).**
Sample of 100 from the 20,029 `gradable:repo` servers (seed = snapshot sha):
33 graded, 49 no-handler-found, 18 clone-failed (all private/gone). Of the
33: 30 at gate 0, 2 at gate 1, 1 at gate 2, none at 3 or 4. Read with the
same code, the PUBLISHED versions of our five grade 1/0/0/0/0 (the working
trees are 4/4/4/4/0 after tonight's commits, unpublished until 6 AM), so the
sentence that is true for a stranger today is "almost nobody, us included,
records their own tool calls," not "we do and they don't." The run hung once at row 39 on a credential prompt that
`GIT_TERMINAL_PROMPT=0` does not stop on Windows; `clone()` now disables the
credential helper and tree-kills on timeout (PLAN.md amendments).

## 0.0.15 — the badge binds the battery (2026-09-01, batch 100B item C2)

## 2026-09-02 — design input: input-disjointness (no code change yet)

Added `design/INPUT_DISJOINTNESS_2026-09-02.md`.

`colonist-one` on the Colony corrected the axis this project aggregates on. Sybil
resistance is usually defined as "are these distinct principals." The question
that decides whether two receipts are two pieces of evidence is "are these
distinct observations," and those come apart without an attacker: two different
agents submitting a byte-identical input set are one observation wearing two
signatures.

This lands on us because we sell the claim that a receipt beats a review by being
grounded in something that happened. That is only true if two receipts are two
happenings.

The cheaper attack they name does not require doing worthless work: omit the
field that would show your evidence was correlated. It is free and it is
indistinguishable from sloppiness.

Owed, and NOT done yet: content-address inputs so disjointness is computable at
all; three-value the settlement (counted / excluded / basis_unknown) so a missing
digest cannot be silently absorbed into "counted"; publish the basis_unknown
count on the badge. Until then, no claim that our aggregation is Sybil-resistant.

Started auditing our own aggregation for the same defect and did not finish.
Recorded as unfinished rather than clean, because unscanned is not clean.

colonist-one's attack on the R1 theorycraft post: "nothing binds the battery."
A badge named WHICH checks ran, but two builds of mcp-vet carrying the same
version string and different check bodies would have produced byte-identical
`checks_run` fields — the badge bound the name of the battery, not the battery.
- **`battery_digest` is a new REQUIRED badge field** (`BadgeReport.schema`
  1 → 2): sha256 over the tool version plus the exact bytes of `checks.py`,
  `grade.py`, `service.py` — the modules that define or register a check,
  listed explicitly so a stray file cannot silently join. Change one byte of
  one check and the digest moves; a verifier recomputes it from the wheel it
  holds. `_assert_required` refuses a badge without it, same as the other four.
- The SVG render gains a `battery` row (`sha256:<12>…`), copy-tested like
  every other drawn string.
- Tests: field required + non-empty, digest moves when a check byte moves
  (battery copied to tmp, `badge.__file__` pointed at it, one byte appended),
  SVG row present. 168 → 171, all green.
- Consumers reading badge JSON: `schema == 2` now carries `battery_digest`;
  a schema-1 badge is still readable but says nothing about which check
  bytes ran. Unpublished at write time — ships in the next 6 AM window.

## 0.0.14 — the receipt stops lying about what ran (2026-09-01 sell-code audit)

Four findings from the full audit of everything we sell, all in the "receipt
claims more than happened" class — the one class this tool cannot afford:
- **Unparseable file graded pass-class.** A SyntaxError produced one `parse`
  info finding under a `checks_run` naming all 8 checks and the verdict
  "informational findings only" — a pass on a file no check ever read.
  Now `scan_source_ex` returns what ACTUALLY ran (`[]` on a parse failure),
  the verdict is `unparseable — 0 checks ran` (not in `_PASS_VERDICTS`), and
  `pass_receipt_gaps` flags a parse+pass receipt as hollow. Tree scans
  intersect `checks_run` across files, so one broken file drops the tree's
  claim too.
- **os.exec*/spawn*/posix_spawn and pty.spawn were not exec sinks.** They are
  now (same class as os.system, message split by shape).
- **`getattr(os, 'system')` walked past the resolver.** Constant-string
  getattr (incl. literal concatenation) now resolves to the canonical call.
  Runtime-computed getattr and dict-dispatch tables remain a DECLARED blind
  spot (`_BS_DISPATCH`) with a slip/control evidence pair the tests enforce.
- **Pruned `.py` files vanished from scope.** `build/`, `venv/`, etc. are
  pruned by NAME, so a first-party module hidden there was neither scanned
  nor listed. Still not scanned; now listed in `files_skipped`.
Docstring gains the two failure classes it had omitted (unsafe-deser,
path-traversal). +6 tests (168 total).

## 0.0.13 — a badge you can SEE (badge.render_svg, R14)

`render_svg(report)` turns a BadgeReport into a self-contained SVG (no fetched
fonts, no network). Pure + deterministic given the report. The image is held to
the SAME discipline as the JSON: every drawn text run passes the copy test, so a
badge picture can never overclaim where the report didn't; and the accent is
STATUS-NEUTRAL (slate for clean, amber for findings) — deliberately NOT
green="safe"/red="danger", which would smuggle the banned verdict back in
through the palette. Footer states plainly: "these checks, this artifact, this
date. Not a safety certification. Verify the receipt." 4 tests incl. determinism,
governed-fields-present, no-banned-word, neutral-color.

## 0.0.12 — the badge report schema + claim-language gate (badge.py, R12)

The public statement built from a scan, governed field-for-field by
BADGE_CLAIM_LANGUAGE_SPEC. `badge_report(target_grade, scanned_at=...)`:
- REQUIRED fields enforced structurally (checks_run, artifact_digest,
  scanned_at, result) — a badge missing what/when/which-bytes REFUSES to build.
- `result` restates the scan's OWN terms (severity counts + neutral verdict),
  never a safety claim. `assert_no_banned_language()` is the runnable copy test:
  raises on certified/safe/secure/approved/endorsed/vetted/guaranteed as a
  verdict — use on every rendered badge AND page/marketing string before ship.
- Pure transform: scanned_at + receipt_id + verify_url passed IN, so same grade
  + same inputs = same bytes (timestamp non-determinism stays at the call site).
- receipt_id/verify_url honestly empty until R13 (ledger receipt) + R15 (verify
  URL) exist — stated, not faked.
- 8 tests incl. required-fields, own-terms result, copy-test catches + allows.
Also: fixed two self-regressions from 0.0.10 (unsafe-deser added to the planted
manifest; the reassignment blind spot given its miss/control evidence pair).

## 0.0.11 — scan a whole server, not just a file (service.scan_target, R11)

The badge lane needs to point at a real MCP server — one file OR a directory —
and get ONE deterministic, receipt-ready grade, without reading files and
stitching grades itself. New `mcp_vet.service.scan_target(path)`:
- Walks .py files in sorted order (prunes __pycache__/venv/etc), grades each
  through the existing grade_source (no second scanner to drift), aggregates.
- Server verdict = worst file's verdict; per-file breakdown kept.
- DETERMINISTIC: source_sha256 is a hash over the sorted (relpath, per-file-hash)
  set, so the same tree always yields the same digest and any edit/add moves it.
- Fails CLOSED: a missing target raises FileNotFoundError, never a clean grade.
- Non-.py files listed as `files_skipped` (honest scope, not silent).
- New CLI: `python -m mcp_vet grade-target <path>` (exit 1 on a high server).
- 8 tests incl. determinism, digest-moves-on-change, worst-file-wins, fail-closed.

## 0.0.10 — the 4th blind spot: exec check now RESOLVES imports (was name-shape matching)

Self-audit (2026-09-01) proved a shell-command backdoor graded CLEAN: `unsafe-exec`
matched sinks by exact dotted spelling, so `from os import system`, `import os as o`,
`builtins.eval`, and `importlib.import_module('os').system` all walked past. A fully
functional backdoor with a valid audit trail got "no findings in checked classes".

- `_import_bindings` + `_canon_call`: every exec/deser call is now resolved through the
  module's own import statements before matching. From-imports, module aliases, `builtins.`
  prefixes, and importlib.import_module dynamic-exec all caught.
- NEW check `unsafe-deser`: pickle/marshal/dill/cloudpickle loads + yaml.load without a
  safe Loader — a whole RCE class that had NO check (audit finding #4).
- BLIND_SPOTS honestly amended: import-form evasion CLOSED; runtime reassignment aliasing
  (`b = eval; b(x)`) documented as the remaining dataflow gap (not papered over).
- 4 new planted-red test groups (import-form evasions, clean negatives, deser fires, deser
  negatives); mutation-verified (reverting the resolver re-breaks the evasion). 18/18 pass.
- The exact backdoor fixture that graded clean now flags unsafe-exec. Proven, not asserted.

# mcp_vet CHANGELOG

## Unreleased — hollow-pass (PASS-must-carry-receipt) check

`grade.pass_receipt_gaps(grade)`: a pass-class verdict ("no findings in checked
classes" / "informational findings only") is a receipt only if the grade proves
it looked — a non-empty `checks_run` over real bytes. Fires on the quesen bug
class / scar #132 (a verifier that greens an EMPTY log reports PASS having
checked nothing): empty checks_run, source hash of zero bytes, no bytes pinned,
or a "no findings" verdict that carries findings. Wired into `verify()` so a
hollow pass is refused even when it reproduces byte-for-byte (reproduction is
consistency, not substance). Ships with a planted-failure test
(test_pass_receipt.py): 4 hollow passes fire, a real clean grade + a findings
verdict stay quiet, verify() rejects reproduced-but-hollow. Not yet released.

## 0.0.9 - 2026-08-31 — unreceipted-allow check

New check: a gate whose BLOCK path returns receipts while its ALLOW path returns
bare verdicts means every permitted action is unreplayable and only refusals are
proven (found live in a counterpart vendor's firewall this week). Reachable red
proven via the real CLI; firing control quiet; two confessed blind spots with
slips-past fixtures (indirect verdict construction; allow/block split across
functions). 137 tests. Catalog cross-link: arcaeon.io fixes #14.
## Unreleased (board C-agent-04 — Ed25519 receipts over a grade)
- **`mcp_vet/receipts.py` — a signed, third-party-verifiable receipt for a
  grade artifact.** `sign_grade(grade, seed)` returns
  `{payload, signature_b64, pubkey_b64, format, alg, canonicalization,
  divergences}`; `verify_receipt(receipt, grade)` returns a bool and
  `verify_receipt_detail()` returns the reasons. The signature does not make a
  grade more correct — it makes it attributable and tamper-evident, which are
  different problems, and the module says so rather than letting a signature
  imply authority.
- **The receipt is small and binds the WHOLE grade.** The payload carries the
  five summary fields (`source_sha256`, `verdict`, `checks_run`,
  `tool_version`, `ts`) plus `responseHash`, a `sha256:<hex>` over the RFC 8785
  canonical form of the entire artifact, blind spots included. Hand
  `verify_receipt()` the grade too and it proves the receipt is about THAT
  grade. Without the grade the verification is bounded and `bound_to_grade` is
  `None`, never `True` — the same refusal-to-mint-a-false-green as
  `verify_audit_ledger`'s three-valued `ok`.
- **Checkpoint/KYA-OS claim names, taken from the spec, not approximated.**
  Fetched 2026-08-30 from `decentralized-identity/kya-os-mcp` (SPEC.md; the
  Checkpoint blog names the draft "KYA-OS · draft-04"). Conforming: `alg` is
  `EdDSA`; the claims `iss`, `sub`, `aud`, `nonce`, `ts`, `requestHash`,
  `responseHash`, `outcome`, `prf` are the spec's names with the spec's
  meanings; hashes are `sha256:<64-char-lowercase-hex>`; canonicalization is
  RFC 8785 (JCS); `iss`/`sub` are self-certifying `did:key` identifiers built
  with the standard multicodec `0xed01` + base58btc encoding.
  Following the R2 brief's read: Checkpoint positions itself as *evidence for
  auditors, not the auditor*, so adopting its shape rather than minting a rival
  format costs nothing and buys the neutral-grader slot.
- **`format` says `checkpoint-kya-v1-compatible`, and the "-compatible" is
  load-bearing.** Five real divergences, listed in `DIVERGENCES` and emitted
  INSIDE every receipt (same rule the grade's blind spots live under — a
  confession filed in a README is a confession nobody reads): (1) the envelope
  is plain JSON, not KYA's detached compact JWS in `_meta.proof`, so a KYA
  verifier will not read ours as-is; (2) we sign the canonical payload bytes,
  not the JWS signing input — deliberate, because it leaves no unsigned
  protected header for an attacker to swap an `alg` or `kid` into; (3) session
  claims (`sessionId`, `scopeId`, `delegationRef`, `clientDid`) are absent,
  because a one-shot grade has no session and a hollow one is theater; (4) no
  DID document is published anywhere, so a verifier learns that ONE key signed
  this and never that it is ours; (5) `source_sha256` / `verdict` /
  `checks_run` / `tool_version` / `target` are mcp_vet extension claims.
  A test asserts the format string never loses its suffix.
- **The key that ships is the key the signature names.** `verify_receipt()`
  checks `pubkey_b64` against the `did:key` in the SIGNED payload's `iss`, so
  substituting a key breaks both the signature and the binding — `iss` is the
  field a human's eye lands on and it must not be free to say anything.
- **Floats are refused, not approximated.** RFC 8785 pins number serialization
  to ECMAScript's algorithm and `json.dumps` does not implement it. Emitting a
  hash over almost-canonical bytes would make every downstream "RFC 8785" claim
  false in exactly the cases nobody tests, so `_canonical()` raises. A grade has
  no floats today; if one appears, this goes red instead of quietly ending
  conformance.
- **New `[receipts]` extra** (`cryptography`), with `[receipts-pynacl]` as the
  declared alternative backend — both are declared because the module runs on
  either and an undeclared fallback is a dependency nobody can audit. Signing
  is an extra rather than a dependency for the same reason `[audit]` is: the
  scanner core stays stdlib-only. Without a backend `sign_grade()` RAISES; it
  does not return an unsigned object shaped like a receipt, and
  `receipts_status_line()` mirrors `audit_status_line()`'s ON/OFF discipline.
- **A key from `$MCP_VET_RECEIPT_KEY` that fails to load is a loud error, not a
  silent fall back to an ephemeral key.** An ephemeral key produces receipts
  that verify perfectly and attribute to nobody — a green that means nothing.
- **25 new tests** (131 total, all green): sign→verify round-trip, tampered
  payload, wrong key, a valid receipt for a DIFFERENT grade, bounded
  verification, `alg` substitution, KYA claim names, `did:key` encoding,
  key-order-independent hashing, float refusal, and the env-key failures.

## 0.0.8 - 2026-08-30 (the audit record reaches in-process callers, not just MCP callers)
- **A GitHub Action, in `action/` (board C-agent-12/13).** A composite action
  that installs mcp-vet, grades `inputs.path`, writes the grade JSON where the
  caller can upload it as a build artifact, appends a summary to the job page,
  and **exits nonzero on a high-severity finding** (`warn-only` opts out). Scope
  chosen deliberately: it does NOT check out your code -- an action that checks
  out on your behalf has to be told which ref, which submodules, which token,
  and gets it wrong for exactly the repos that care. It reads nothing from the
  event payload, the actor, or a token, so a **bot-triggered push is graded by
  the identical path as a human's pull request**, which is the case that
  actually matters: the agent opening the PR is the one whose server nobody
  read.
- **The action's body is `action/run_vet.py`, not a `run:` block of shell.** An
  action whose logic lives in YAML can only be tested by pushing to GitHub and
  watching a run go red, which means it gets tested by strangers on their own
  repos. Everything -- file selection, the summary, and above all the exit code
  -- is a plain script driven by environment variables, so `test_action.py` runs
  the identical code path locally.
- **Three exit codes, and the third one is the point.** `0` clean or warn-only,
  `1` at least one high-severity finding, **`2` the scan could not run** (path
  missing, no Python under it, mcp-vet not installed, mcp-vet not emitting
  JSON). A scan that never happened is deliberately neither a pass nor a
  finding: "we found nothing" and "we looked at nothing" are the two states a
  security gate must never blur. A missing binary is caught and mapped to 2
  rather than allowed to raise, because Python's default exit on an uncaught
  exception is 1 -- a tooling failure would have been read as a security result.
  Only **high** fails the job; medium here is heuristic by construction
  (entropy, gate ladders) and a gate that reds on a heuristic gets switched off
  by its first false positive.
- **The job summary carries the blind spots, not just the findings.** Verdict,
  checks run, findings table, the full declared-blind-spot list in a `<details>`
  block, and the not-a-vetting-authority line, every run. A CI summary that
  prints only what was found teaches its reader that green means safe, which is
  the one claim this project refuses to make. The check list and blind spots are
  read off the grades the run produced, the same rule `grade.py` follows for
  `checks_run` -- a summary keeping its own copy is a second source of truth
  that will drift from the first.
- **The artifact holds whole grades, unmodified.** Each entry is a standalone
  re-runnable artifact (`mcp-vet verify`), wrapped in an envelope carrying the
  worst verdict across files -- worst, never averaged: a repo with nine clean
  servers and one hardcoded live key is not 90% fine. Vendored trees (`.venv`,
  `node_modules`, `build`, `site-packages`) are skipped, because a red the
  caller cannot fix is how a gate gets switched off for good.
- **Inputs are passed as env, never interpolated into a shell body.**
  `${{ inputs.version }}` pasted into a `run:` line is a command injection, in
  an action whose entire subject is supply-chain hygiene. A test asserts no
  `${{` appears in any step body.
- **The summary print is encoding-guarded, and the step outputs are written
  first.** Found by running the script for real rather than by reading it: a
  GitHub runner on Windows hands Python a cp1252 stdout, the summary's status
  glyph is not in cp1252, and the resulting `UnicodeEncodeError` exited **1** --
  this action's code for high-severity findings. A console encoding would have
  been reported as a security result, with the step outputs never written
  because the crash came before them. Console writes now fall back to a
  replacing encode, and everything a downstream step consumes lands on disk
  before anything touches a console we do not own. (Same failure class the
  connector already keeps a test for; it turned up here on the first real run.)
- **`test_action.py` -- 23 tests, none of them needing GitHub.** Red: the
  planted credential fixture exits 1 with three high-severity findings. Green: a
  clean server exits 0. Plus a medium-only file that must NOT fail, a directory
  that grades both files and takes the worst verdict, vendored dirs skipped, a
  missing path and an empty directory and a broken mcp-vet install all landing
  on 2 with no artifact written, every grade in the artifact re-verified through
  `mcp_vet.grade.verify`, the summary appended (not overwritten) to a shared
  `$GITHUB_STEP_SUMMARY`, the whole run surviving a cp1252 console with
  its outputs intact, the whole thing running with no `GITHUB_*` vars at
  all, and five guards on `action.yml` itself: it stays composite and still
  calls the script these tests exercise, it never checks out and never needs a
  token or a prompt, no input is interpolated into shell, every script input is
  wired through the grade step's `env`, and every declared output matches a name
  the script actually writes.
- README: new **"Run it in CI (GitHub Action)"** section with a copy-paste
  workflow (checkout, grade, `upload-artifact` with `if: always()` so the grade
  is published even when the job fails), the input table, and the exit-code
  contract.
- **`scan_recorded(path)` / `grade_recorded(path)` — new library-level entry
  points in `mcp_vet.server` (board C-agent-31).** `mcp_vet_scan` /
  `mcp_vet_grade` were only recorded when a caller reached them through an MCP
  round-trip; anything in-process that wanted the scan/grade result plus the
  audit row had no supported way to get both, because `_record_call` was
  module-private. The `arcaeon` connector was the concrete case: its `vet_scan`
  / `vet_grade` called `mcp_vet.checks.scan_source` / `mcp_vet.grade.grade_source`
  straight, which scans and grades correctly and writes nothing to mcp-vet's
  ledger — a vet call made through the connector left no row, while the
  identical call through mcp-vet's own server did. `scan_recorded` /
  `grade_recorded` run the exact read-then-check-then-`_record_call` sequence
  the MCP tool handlers run (same failure recording on a missing path), as an
  ordinary function call. `mcp_vet_scan` / `mcp_vet_grade` are now thin
  wrappers over them, so there is one implementation of "scan/grade, and
  record it," not two that can drift.
- **`SCAN_DESCRIPTION` / `GRADE_DESCRIPTION` — the two tool descriptions
  pulled out as module constants**, importable instead of hand-copied. A
  hand-copied description (which is what the connector had) goes stale the day
  this file's wording changes and the copy doesn't; an imported constant
  cannot.
- No behavior change to the MCP surface: `mcp_vet_scan`, `mcp_vet_grade`,
  `mcp_vet_audit_verify` are unchanged, same three tools, same ledger format.

## 0.0.7 - 2026-08-30 (we close the finding we published on ourselves)
- **Why 0.0.7 and not more prose under 0.0.6.** 0.0.6's headline is *we fail our
  own new check*, and the published self-audit says `mcp_vet/server.py` scores
  **high**, four gates false. Fixing that inside the same version would overwrite
  the artifact the version exists to preserve. It is also not a documentation
  change: the server's public tool list grew a third tool, the CLI grew a
  subcommand, and there is a new optional extra. Two versions, two states, both
  still readable - which is the only reason the 0.0.6 confession was worth
  making.
- **`mcp_vet/server.py` now keeps a real audit trail, and passes its own MCP08
  check honestly (board B2b).** Every `mcp_vet_scan` / `mcp_vet_grade` call
  appends **one** hash-chained row to an `arcaeon_ledger` (0.7.0) file:
  `tool`, ISO-8601 UTC `ts`, `args.path`, **`source_sha256` of the exact bytes
  read**, the finding count and the verdict. The digest is the load-bearing
  field - it makes a row re-testable the same way a grade artifact is, by
  anyone holding the file.
  - **The rule was: meet the gates with a record, not with source text.** Every
    gate has a RUNTIME test (`test_audit_ledger.py`, 18 new): a scan through the
    SDK's in-process client leaves exactly one row; the row carries the four
    fields; a tampered row is named **by line number**; a failed call is still
    recorded (`error` set, `source_sha256` null) rather than vanishing. The
    static check is allowed to go quiet only because those pass. Arranging code
    to please our own heuristic is the exact dishonesty this project exists to
    catch, and the temptation was real - three of the four gates could have been
    bought with a well-named function and an import.
  - **New tool `mcp_vet_audit_verify`** and **new CLI `mcp-vet audit-verify
    [ledger]`** - recompute the chain, report `ok` / `rows` / `breaks` /
    `first_break`. That is gate 4, and it ships outside MCP on purpose: a record
    only checkable through our own server is a claim, not evidence. `ok` is
    passed through **three-valued** exactly as `arcaeon_ledger` returns it -
    True / False / **None when the scan was bounded** - and the CLI exits 0 only
    on a full green, 2 on a break, **3 on bounded-or-empty**. No rows is not a
    green.
  - Ledger path: `$MCP_VET_AUDIT_LEDGER`, else `~/.mcp_vet/audit.jsonl`. Read at
    CALL time, never cached at import, so an operator who sets it in the
    launching shell is not ignored. A suite-wide `conftest.py` redirects it to
    tmp - a test run that quietly grows the developer's real audit log is the
    kind of unannounced side effect this tool complains about elsewhere.
- **Three honest edges, none of them papered over.**
  1. **`arcaeon-ledger` is an optional extra `[audit]`, not a dependency.** The
     scanner core stays stdlib-only; the trail is a property of RUNNING as a
     server, not of grading a file. Without it the server still runs and the
     record is **OFF** - never silently: the status line is in the server
     instructions, in every `mcp_vet_audit_verify` reply, and on stderr at
     startup. Tested by disabling the import and asserting the scan still works,
     nothing is written, and the reply says so.
  2. **`mcp_vet_audit_verify` does not record itself.** A verify that mutates
     its own subject can never report on it cleanly. That is one of three tools
     outside the trail - precisely the per-handler coverage gap we already
     confess as a blind spot. We sit in our own blind spot knowingly, with a
     test pinning it as deliberate.
  3. **A ledger write failure raises through the tool call.** An audit trail you
     cannot write to is a fact the caller needs; swallowing it to keep the scan
     looking healthy is the silent green.
- **A new blind spot, opened by the fix and confessed with it
  (`_BS_MCP08_OPTIONAL`).** Our gate-1 pass is conditional on an import the
  static pass cannot see: in a bare install the write never runs and the file
  still scores clean. Evidenced like every other entry - two fixtures running
  the same server, identical but for the guarded call, one scoring 0 and one
  firing **high**. Same runtime behaviour in a bare install, opposite verdict.
  Finding the fix's own gap and shipping it in the same change is the whole
  standard here; the alternative was to enjoy the clean score quietly.
- **The self-audit moves, and only where it should.** `self_audit_grades.json`
  re-run: `mcp_vet/mcp_vet/server.py` goes **high (all four gates false) ->
  clean, 0 findings**, all four gates met. The other three targets are
  **unchanged and still red** - `mcp_public_safety` and `arcaeon-distill` high,
  `arcaeon_ledger_mcp` medium on gate 2. A self-audit where everything goes
  green at once is a self-audit that stopped looking.
- Suite **66 -> 84** green. Two v0.0.6 tests were INVERTED rather than deleted,
  with the old assertion quoted in the docstring: the check firing on our own
  server, and the server advertising two tools.

## 0.0.6 - 2026-08-30 (MCP08: the audit-trail check nobody else runs)
- **Sixth check class: `audit-record` / OWASP MCP08 (board B2).** Every other class
  here asks "can this server be made to do something dangerous"; `secret-in-code`
  asks "is it leaking at rest." This one asks a third question: **if it did
  something, could anyone prove what.** That is the differentiator, and the
  research pass is why (`projects/online_business/BATCH100_R_OWASP_MCP08_2026-08-30.md`):
  Snyk Agent Scan's ~21 issue codes (E001-E006, W001-W021) contain **zero**
  audit/telemetry checks. MCP08 is the one category on the list that is about a
  **control being present** rather than a bug being absent - awkward for a
  vulnerability scanner, natural for a grade. Design: `design/MCP08_audit_record.md`.
  - **Four gates, one finding per server, severity = the first gate not met.**
    presence (a tool call produces a record at all) -> `high`; completeness (tool
    name + timestamp + args/digest) -> `medium`; tamper-evidence (chain / hmac /
    ledger, not a plain log) -> `medium`; reconstructability (a verify/replay path
    exists) -> `low`; all four met -> silence. The finding carries a **`gates`
    dict** so a reader sees the whole ladder, not just the rung that failed.
  - Presence evidence: a logging call **that names the tool**, an append-mode file
    write, a DB `INSERT`, a ledger-style `append`, an OpenTelemetry span - reached
    from a decorator-registered handler **or a hand-rolled `tools/call` dispatcher**
    in <= 2 hops. The dispatcher shape is not optional: arcaeon-ledger's own MCP
    server speaks JSON-RPC directly, and a check that only understood `@mcp.tool()`
    would have scored the reference implementation of the control it is testing for
    as having no handlers at all. The <= 2 hops matter for the same reason - the
    audit write nearly always lives in an `_audit(...)` helper, not inline.
  - **Precision is the whole game again.** A `print()` is never a record. A
    `logging.info("done")` is not a record: a log line that cannot say WHICH tool
    ran cannot answer the question MCP08 asks. The check only runs on a file that
    both registers a handler **and** serves, because asking a module fragment where
    its audit trail is, is noise. And an append-mode `open()` counts for presence
    but **not** for tamper-evidence: OWASP lists "append-only or write-once media"
    under that gate, but a plain `open(p,"a")` is one letter from a rewrite and
    statically indistinguishable from WORM storage - counting it would let a plain
    unchained log pass gate 3 and collapse the whole ladder.
  - Everything is AST, never a text scan, and that is a lesson taken off our own
    scar: `zero-auth`'s whole-file substring test is silenced by the word *author*
    in a docstring. `mcp_vet/server.py`'s tool description contains the sentence
    "Feed it back to `mcp_vet.grade.verify()`" - a text scan would have awarded it
    gate 4 for a sentence about itself.
- **We fail our own new check, and it is the loudest finding in the file.**
  `mcp_vet/server.py` scans whatever file it is handed and keeps **no record of
  having done it**: no log line, no ledger row, no span. `audit-record` returns
  **high** on it, gates all four `false`. So does `mcp_public_safety/server.py`.
  Our published self-audit is no longer "0 findings across 3 servers" and the
  README says so in those words. The tool that sells an audit-trail check did not
  keep an audit trail - written down rather than fixed-then-announced, because the
  finding is the more useful artifact.
- **arcaeon-ledger's MCP server is the reference presence pattern, and it comes
  back `medium`.** Gates 1, 3 and 4 read `true` - a ledger-style append at line
  303, an append-only hash-chained library import, `verify_file()` for replay.
  Gate 2 reads `false`, and honestly: the record payload is the *caller's* dict,
  so the file itself never guarantees a tool name or a timestamp is in it (the
  `ts` is added by `Ledger.append` one file away, which a static pass cannot see;
  the tool name genuinely is not added at all). The finding names the missing
  fields instead of quietly passing the gate. That is the answer the task asked
  for: not "all four," but exactly which gate the static heuristic cannot see.
- **Five new blind spots, and a second evidence table for a new direction of
  error.** `BLIND_SPOT_EVIDENCE` only ever modelled MISSES - a fixture scoring 0
  plus a control that fires. MCP08 asks whether a control is PRESENT, so it can
  fail the other way too, and **a false red is the more expensive error for this
  project**. New `FALSE_RED_EVIDENCE` pairs each over-report with a fixture that
  really does draw the wrong red plus the reason in plain language. Three misses:
  gates are per-FILE so a server that records one tool and drops the rest passes
  presence; the check is only asked of a file that both handles and serves;
  tamper-evidence is a file-level smell that an unrelated hash chain satisfies.
  Two false reds: a record written by middleware or an imported decorator is
  invisible (fully audited server, reported high), and a sink whose durability
  lives in `logging.ini` - syslog, journald, a write-once bucket - reads as a
  plain rewritable log (reported medium). 11 -> 16 blind spots.
- 15 new tests: 14 in `test_audit_record.py` (the full ladder, the three
  precision negatives - print, unnamed log line, not-a-server - our own two
  servers firing on themselves, arcaeon-ledger's exact gate readout, and the
  `gates` key appearing only where it means something) plus a metadata test that
  every false red really fires. 51 -> 66 tests, all green.
- **Version bumped to 0.0.6, not held at 0.0.5.** The 0.0.5 note set the rule: "if
  a grade's *shape* ever changes, that is a bump." It changed three ways - the
  registry gained a class, `Finding` gained an optional `gates` key, and `_verdict`
  gained a `low` tier - so a prior grade of a server with no audit trail no longer
  reproduces. `gates` is **omitted** from `as_dict()` when unset rather than
  serialized as `null`, so findings from the other five classes are byte-identical
  to what 0.0.5 emitted and old grades over those still `verify()`.
- **The self-audit target list was widened, because it was quietly short.**
  `mcp_vet/server.py` has shipped since 0.0.5 and was never in `scan_own.py` /
  `grade_own.py` TARGETS, so the published "all our servers" set excluded the one
  server this project is directly responsible for. Same failure class as the
  `arcaeon-distill` locator that silently stopped matching in 0.0.5. Now 4
  servers, 4 findings, all four grades still reproducing under `verify()`.
- **Repo-wide precision sweep, and it found a real over-report.** ~1,570 Python
  files: the first pass drew 9 audit hits, one of them on
  `projects/arcaeon_connector/test_connector.py` — a TEST that drives a server
  over MCP, not a server. The dispatcher heuristic was matching the bare literal
  `"tools/call"` anywhere in a function, and a client builds that string as a
  dict VALUE. It now requires the literal to be BRANCHED ON (an `if method ==
  "tools/call"` comparison or a `match` case): sending the message is not
  handling it. Second sweep: 8 hits, every one a real MCP server, zero on tests,
  clients or library code.
- The `test_mcp_server.py` CLEAN fixture grew an audit trail. A served MCP server
  whose tool calls leave no record is not clean any more, so the clean fixture had
  to become one - a hash-chained, complete, verifiable per-call record. It is now
  the worked example of what passing MCP08 looks like.

## 0.0.5 — 2026-08-30 (installable package + mcp_vet is itself an MCP server)
- **Fifth check class: `secret-in-code` / MCP01 (board F4).** The first four all ask
  "can this server be made to do something dangerous." This one asks a different
  question — is the server, at rest, right now, handing a credential to anyone who
  reads the source (CWE-798 / OWASP A05). Implemented from `design/MCP01_secret_in_code.md`
  against the planted fixture `tests/fixtures/secret_in_code_server.py`; the check
  registers itself with `@register("secret-in-code")`, so `checks_run` picked it up
  with nothing else edited — the registry doing exactly the job it was added for.
  - Three pattern families. **Vendor key shapes** (AWS `AKIA`/`ASIA`, Stripe
    `sk_live_`/`rk_live_`/`whsec_`, OpenAI `sk-`/`sk-proj-`/`sk-svcacct-`, GitHub
    `gh[pousr]_`/`github_pat_`) are `high`: a prefix is a fingerprint, not a guess.
    **Entropy-gated literals** bound to a `*_KEY`/`*_TOKEN`/`*_SECRET`/`PASSWORD`
    name — including dict entries (`{"Authorization": "..."}`) and keyword args
    (`Client(api_key="...")`), both realistic leak sites — are `medium`, because
    entropy cannot tell a leaked key from a well-formed-looking hash, and severity
    should track confidence the way `ssrf` already does it. **`.env`-shaped
    `NAME=value` lines** quoted in a docstring or a comment: a key does not have to
    be *assigned* to leak, a pasted README block leaks it just as hard. Comments are
    read via `tokenize`, not a raw-source regex, so a `#` inside a string literal is
    not mistaken for one.
  - Precision is the whole game in this class, so the gates are mean on purpose:
    length >= 16, Shannon entropy >= 3.5 bits/char, no whitespace, must mix letters
    and digits, placeholder vocabulary (`changeme`, `your_`, `<KEY>`, `${...}`)
    rejected, and vendor **test/publishable prefixes exempt** — `sk_test_` and
    `pk_live_` are meant to be hardcoded or meant to be public, and a false red on a
    stranger's fixture key is exactly the noise that gets a scanner uninstalled.
    Env-loaded secrets are silent by construction rather than by allowlist: the value
    has to be an `ast.Constant`, and `os.environ[...]` is a Subscript.
  - Findings are **redacted** (`ghp_FA... (40 chars)`). A scanner that prints the key
    it found is a leak with a report attached. Multi-line literals report the line the
    secret is actually on, clamped to the node's real source span, so a docstring
    finding does not point at the opening quote.
  - 17 new tests (`test_secret_in_code.py`), precision cases outnumbering detection
    cases: 9 vendor shapes, entropy class, dict/kwarg sites, docstring and comment
    env lines, plus the deliberate non-catches (test keys, env-loaded, concatenated,
    placeholders, prose) and the fixture asserted at **exactly 3 findings on lines
    23/27/31 with the `os.environ.get` control at line 38 silent**. 34 -> 51 tests.
  - **Four new evidenced `BLIND_SPOTS`**, per the F20 convention (a fixture scoring 0
    plus a minimally-different control that fires): test/publishable prefixes never
    flagged; runtime-concatenated or base64-decoded credentials never being a single
    literal; the letters-and-digits requirement letting an all-alphabetic credential
    slip; and the bare 40-char AWS secret shape only counting when the name says what
    it is. Not added, because it cannot be evidenced from a source string and is scope
    rather than shape: a real `.env` sitting beside the server on disk is never opened
    (a line scanner over a non-Python file, not a tree walk) — filed to the roadmap.
  - One deliberate widening of the design: the env-line pattern tolerates spaces
    around `=`, so a quoted `API_KEY = "..."` assignment line inside a docstring is
    caught alongside a true `.env` line. Same leak, same evidence, same gates.
  - Self-audit re-run: `checks_run` went from `['unsafe-exec','ssrf','path-traversal',
    'zero-auth']` to the same four plus `'secret-in-code'`, `blind_spots` 7 -> 11, and
    **all three of our own servers still score 0 findings**. The 0 is proven non-vacuous
    the same way as v0.0.1: appending one `sk_live_` literal to a copy of the real
    `mcp_public_safety/server.py` fires at that line. Swept the wider repo as a
    precision smoke test too (~400 files): every hit was a planted fake in a test
    file — including, pleasingly, the secret scrubber's own fixture — and zero hits in
    live code.
- **The grade artifact stopped lying about itself (board F20).** Two metadata drifts,
  both pointing the same way — the artifact understating the tool, which is the worst
  direction of error for something whose only product is an honest self-report.
  `checks_run` was a hand-kept literal saying `['unsafe-exec','ssrf','zero-auth']`
  while `path-traversal` had been running since 0.0.4, and `blind_spots` still
  confessed three gaps 0.0.4 closed (dynamic-import evasion, aliased taint,
  path-traversal). Every grade emitted since 0.0.4 was wrong in both fields.
  - `checks.py` now has a **check registry**: `@register("name")` on each check,
    `scan_source` runs the registry, and `grade_source` reads `checks_run` off
    `check_names()`. There is no second list to keep in step, because a second list
    is where drift lives. (Adding a check = one decorated function; nothing to
    append to in `grade.py` any more — `CHECK_CLASSES` is gone on purpose.)
  - `BLIND_SPOTS` is now known-open gaps ONLY, and each carries evidence:
    `BLIND_SPOT_EVIDENCE` pairs every entry with a fixture the checker scores 0 on
    and a minimally-different control it does fire on, so a 0 proves the named gap
    rather than an inert fixture. Seven entries, four of them newly found and proven
    while writing the tests: taint that only follows a bare parameter name
    (`open('/data/' + name)` slips), handlers registered imperatively via
    `add_tool()` never being entered, keyword-only/`*args`/`**kwargs` parameters not
    counting as tool input, and two in the transport check — the auth test is a
    whole-file substring scan, so the word *author* in a docstring silences it, and
    a transport read from the environment is invisible because only a literal
    counts. Kept: multi-hop taint (our own `server.py` demonstrates it) and the
    static-only ceiling. Artifact strings are ASCII so the grade stays diffable.
  - 7 new tests (`test_grade_metadata.py`): every check that fires must be named in
    `checks_run`; `checks_run` must equal the registry; no blind spot may name a
    check that runs; the three 0.0.4 closures must not still be confessed (with a
    live red proving each is caught); every blind spot has evidence; every evidence
    fixture scores 0; every control fires. 27 -> 34 tests, all green.
  - Old grades still `verify()`: reproduction compares bytes, findings and verdict,
    none of which moved. `self_audit_grades.json` regenerated — it was still stamped
    `0.0.3`, two versions stale, so the same run also refreshes `tool_version`.
  - Same run caught a silent shrink: `arcaeon-distill` had moved out of the repo and
    the locator glob quietly stopped matching, dropping the third server from the
    published self-audit without an error. `scan_own.py` / `grade_own.py` now search
    beside the repo too (target labelled `../arcaeon-distill/...`) and print a loud
    warning when they come up empty. Back to 3 servers, 0 findings, all reproducing.
  - **No version bump.** Stayed at 0.0.5: the schema is still 1, `verify()` semantics
    are unchanged, prior artifacts still reproduce, and 0.0.5 shipped the same day
    and has not been published. Bumping would have broken the `pyproject` ==
    `__version__` == newest-CHANGELOG-heading triple that `test_packaging.py` guards
    for no reader benefit. If a grade's *shape* ever changes, that is a bump.
- **Packaging (C-agent-23).** Real `pyproject.toml`: distribution `mcp-vet`, import package
  `mcp_vet`, MIT (`LICENSE` added), `requires-python >=3.10`, console script `mcp-vet`.
  Runtime `dependencies = []` on purpose — the scanner core is stdlib-only, because a
  security checker that drags in a dependency tree is a supply-chain surface of its own
  and the whole pitch is a grade a skeptic can re-run cheaply. The MCP SDK lives in the
  `[mcp]` extra. Verified by `pip install -e .` into a clean venv + `mcp-vet --help`.
  Also fixed a real drift: `__version__` still said 0.0.3 while the CHANGELOG was at
  0.0.4, so every 0.0.4 grade artifact carried the wrong `tool_version`. New
  `test_packaging.py` now asserts pyproject == `__version__` == newest CHANGELOG heading,
  so that particular lie cannot be told twice. This file re-sorted newest-first.
- **MCP server (C-agent-02).** `mcp_vet/server.py` exposes the checker over stdio MCP with
  two tools: `mcp_vet_scan(path)` returns the findings list, `mcp_vet_grade(path)` returns
  the same grade dict the CLI emits, `source_sha256` included — so an agent gets the
  re-testable artifact, not a summary of one. New `mcp-vet serve` subcommand. Supports the
  `mcp` SDK 2.x (`MCPServer`) and falls back to 1.x `FastMCP` by import probe.
- 12 new tests (6 packaging + 6 server: a full protocol round-trip through the SDK's
  in-process client, planted-vulnerable fixture must return the planted finding at the
  planted line, clean fixture must return none, the grade tool's artifact must match the
  CLI's byte for byte, that artifact must survive `verify()`, and a missing file must
  ERROR rather than answer "no findings" — a silent green is the worst failure a scanner
  has). 15 -> 27 tests, all green. Also proven out of process: the installed `mcp-vet
  serve` console script driven as a real stdio subprocess by the SDK client.
- **A miss on our own code, disclosed rather than filtered.** The server hands a
  caller-named path to the scanner — `mcp_vet`'s own `path-traversal` class pointed at
  itself. Reading the named file is the tool's whole function, so the exposure is by
  design; what is NOT by design is that `mcp_vet scan mcp_vet/server.py` returns **0
  findings**. The taint runs `path` -> `_read(path)` -> `read_text`, one hop through a
  helper function, which is precisely the "multi-hop taint through function calls"
  blind spot v0.0.4 left open. So our own new server is a live demonstration of the
  gap we already published. Stated in the README, not scrubbed. Mitigation for now is
  operational, not analytical: stdio/local only, never bound to a network transport
  without auth in front.

## 0.0.4 — 2026-08-30 (three named blind spots CLOSED)
- **dynamic-import evasion** now caught: `__import__('os').system(x)` (was a documented v0.0.3 blind spot).
- **aliased taint** now tracked: `p = tool_arg; urlopen(p)` traces back to the param via a fixpoint alias pass (SSRF + the new path-traversal both use it).
- **path-traversal** is a NEW check class: a tool handler passing tool input into open()/read_text/write_* is flagged as arbitrary file access. `unsafe-exec`, `ssrf`, `path-traversal`, `zero-auth` = 4 classes now.
- 10/10 check tests (3 new reds + 2 new negatives), 5/5 grade tests. Own 3 servers regraded 4-class, still 0 findings, still reproduce. README blind-spots list trimmed to what actually remains (multi-hop taint, static-only).

## 0.0.3 — 2026-08-29 (the re-testable grade — R3 wedge made concrete)
- New `grade` module + CLI: emits a grade artifact that pins the scanned bytes
  (source_sha256), carries its own blind-spots inline, and states a verdict.
- `verify(prior_grade, source)` re-runs and confirms reproduction — a grade a
  skeptic can re-run and get the same answer, or it was lying. 5/5 tests incl.
  planted reds (wrong bytes + scrubbed-findings both fail to reproduce).
- Self-audit grades emitted for all 3 of our own MCP servers (self_audit_grades.json),
  each proven to reproduce. This is the artifact the public self-audit post points at.
- Repositioning (R3, verified): we do NOT compete with Snyk Agent Scan (15+ checks,
  runtime) on scanning; the wedge is the OPEN, re-testable, self-confessing grade
  that closed enterprise scanners don't publish.

## 0.0.2 — 2026-08-29 (self-audit hardening before going public)
- Ran the checker against a deliberately-vulnerable server (the "poke holes" a stranger
  would try). Found + fixed one false negative: `subprocess.Popen(["sh","-c",cmd])`
  (shell via explicit `sh -c`, shell=False) is now caught. 2 new reds + a safe-argv negative.
- Documented the remaining honest blind spots in the README (dynamic-import evasion,
  aliased taint, path-traversal) rather than shipping them silent. 9/9 tests.

## 0.0.1 — 2026-08-29 (foundation, Daniel's Option-2 greenlight)
- AST-based checks: unsafe-exec, ssrf (taint-aware high/medium), zero-auth
  (network transport w/o auth; stdio exempt). Every finding carries file+line.
- 7/7 tests: planted red + clean negative per class.
- SELF-AUDIT run against our own 3 MCP servers → 0 findings, proven non-vacuous
  by an injected-red engagement check on the real server file.
- WIP framing throughout; no vetting-authority claims. Nothing published yet.
