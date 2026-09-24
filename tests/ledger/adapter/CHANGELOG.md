# Changelog — arcaeon-adapter

## Unreleased

- README, "The honest limit": one more line under "blind to": the proxy is run by the same party as the agent, so it is not an outside witness; it proves the agent could not skip or edit a row, not that the operator could not. Stated in public on 2026-09-23 (Colony, Touchstone thread) before it was in the README; docs only, no release.

## 0.2.0 — 2026-09-23 (the tape: an agent-side record `reconcile` can check for COMPLETENESS; HTTP forward mode; duplicate and invalid ids never lose a call)

The entries below down to 0.1.4 were staged as dated Unreleased entries on the completeness branches after 0.1.4 (a4d06d5) was cut, and ship together in 0.2.0: a minor bump because the tape and `--http-forward` are new surface. The README keeps the `mcp-name: io.arcaeon/adapter` marker; the sdist keeps excluding `registry/` and `RELEASE_*.md`.

### 2026-09-23 (branch completeness-slice3): invalid ids are taped `invalid_id`, never dropped

- **Why.** The observer ignored a `tools/call` whose JSON-RPC id was a boolean (`_id_key` gave it no key, so it was skipped), while arcaeon-receipt's call_proxy taped it and paired the upstream's answer to it. A clean stream carrying `id: true` reconciled as MISSING on the agent side. JSON-RPC 2.0 says an id is a string, a number, or null, so such a call is invalid; but it was sent, and a completeness recorder must not drop a sent frame.
- **The rule, identical on both sides (arcaeon-receipt `completeness-slice2` has the same change):** a `tools/call` whose id is not a string, number or null (true, false, an object, an array) is an INVALID call. It gets exactly one tape row and one seam row, written at once, with `status: "invalid_id"`, no response digest, and `rpc_id` as compact JSON (`"true"`, `'{"k":1}'`); no answer is ever paired to it. A null or absent id is still a notification: no row. Both tapes carry the same row with `resp: null`, so reconcile reads it MATCHED with the row marked invalid.
- `tape.py`: NEW `valid_rpc_id()`, `render_invalid_id()`, `INVALID_ID`, `TapeWriter.invalid_call(params, rpc_id)` (takes the next index, row finished at once, still committed in index order behind an open earlier call). The row format doc lists `invalid_id`.
- `observer.py`: `observe_client_frame` routes an invalid-id `tools/call` to NEW `_invalid_call` (seam row `status: invalid_id`, `ms: 0`, tape `invalid_call`, counted in `calls_seen`); it is never queued, so an answer carrying that id pairs with nothing. The stdio and HTTP forward paths share it.
- Tests (written first; the 6 non-trivial ones run red on 977a0c5): `test_observer.py` +4 (a batch with ids true, 1, "x", false, {"k":1}, [1] is 6 seam rows and 6 tape rows, the four invalid ones `invalid_id` with no answer, unscoped and in an HTTP scope; a null/absent id is still no row; break arm: the old predicate fails the check). `test_tape.py` +1 (`invalid_call` index order, nothing to close later, the predicate's table). `test_http_forward.py` +4: forward mode tapes `true` as `invalid_id` and relays all three answers unchanged; NEW cross-repo `test_cross_repo_invalid_ids_match_on_both_tapes` (client -> adapter --http-forward -> call_proxy -> upstream, ids [true, 1, "x"]: `MATCHED 3 of 3`, SKIPs with the reason when the call_proxy found has no `_valid_rpc_id`); break arms on the agent side (unit and cross-repo) and the tool side (`call_proxy._valid_rpc_id` forced True) each fail. Adapter suite 208 -> 217 passed (ARCAEON_RECEIPT_REPO = the fixed arcaeon-receipt worktree; PYTHONPATH = the checkout and its adapter/).

### 2026-09-23 (branch completeness-slice3): duplicate ids pair FIFO; Connection-named headers stripped

- **Why.** Review finding: `SeamObserver._pending[key]` was overwritten when a batch or a session reused a JSON-RPC id. The first call lost its seam row entirely (not even in `session_end.unanswered`), held its tape row open until session end (so every later tape row waited behind it), and the second call was taped with the answer meant for the first. arcaeon-receipt's call_proxy kept the FIRST answer per id instead, so the two tapes disagreed at that index on a clean run (fixed adapter against the old call_proxy: `ALTERED at call 2`). Duplicate ids violate JSON-RPC, but a completeness recorder must never silently lose a seam row.
- **The rule, identical on both sides (arcaeon-receipt `completeness-slice2` has the same change):** open calls are queued per (scope, id) in send order; an answer pairs with the OLDEST open call of its id; a call never overwrites another; every sent call gets exactly one tape row and one seam row; a call still unpaired at session end is `unanswered`. Consequence stated, not hidden: a reused id's answer goes to the oldest open call of that id even if that call was left open by an earlier 202; both sides do the same, so the tapes agree.
- `observer.py`: `_pending` is (scope, id) -> list of open calls, oldest first (`_enqueue`, `_take_oldest`, `_take`). `observe_client_frame` now returns one handle per call opened (it returned keys, which could not tell two calls of one id apart); `close_unanswered(handles, reason=)` closes exactly those calls that are still open. `flush_pending` rows every open call, in open order. The stdio path passes no scope and gets the same rule.
- `http_forward.py`: headers NAMED in a `Connection` header are not forwarded, in either direction (RFC 9110 7.6.1), alongside the fixed hop-by-hop set. NEW `_connection_named()`. The PAIRING docstring states the FIFO rule.
- Tests (written first; the 9 non-break-arm tests run red on a5bf8a6): `test_observer.py` +6 (batch ids 1,1,2 -> 3 seam rows + 3 tape rows each with ITS answer, unscoped and in an HTTP scope; a reused id across frames answers the oldest first; two unanswered duplicates are two `unanswered` rows; `close_unanswered` by handle; break arm: the old overwrite `_enqueue` fails the check). `test_http_forward.py`: the duplicate-id test now claims the pairing (3 tape + 3 seam rows, answers in order, nothing left for session end); NEW Connection-named headers stripped both ways + break arm (`_connection_named` returning nothing); NEW cross-repo `test_cross_repo_duplicate_ids_match_on_both_tapes` (client -> adapter --http-forward -> call_proxy -> upstream, one batch 1,1,2: `MATCHED 3 of 3`, SKIPs with the reason when the call_proxy found does not pair FIFO); break arms: overwrite pairing on the agent side (unit and cross-repo) and on the tool side (`_ToolTape._enqueue`) each fail. Adapter suite 197 -> 208 passed (ARCAEON_RECEIPT_REPO = an export of the fixed arcaeon-receipt branch; PYTHONPATH = the checkout and its adapter/).

### 2026-09-22 (branch completeness-slice3): the HTTP forward mode

- **Why.** The tape only existed where the adapter could sit in a stdio pipe. An agent talking to an HTTP MCP server had no agent-side tape, and the slice-two cross-repo demo needed a test-only stdio-to-HTTP bridge to fake one.
- NEW `arcaeon-adapter --ledger L --tape T --http-forward URL --listen HOST:PORT` (`arcaeon_adapter/http_forward.py`, stdlib `http.server` / `http.client` / `zlib` only). A local listener the agent is pointed at; each request is forwarded to the upstream MCP endpoint and the answer is streamed back with the same status, reason, end-to-end headers (nothing added, no `Server`/`Date`) and body bytes. Hop-by-hop headers are not forwarded; a chunked or close-delimited body is re-chunked (same bytes). A request to `/` goes to the upstream URL's own path. `--upstream-timeout` (default 300 s) bounds upstream reads. Bound address printed on stderr; Ctrl+C / SIGTERM / Ctrl+Break end the session cleanly.
- The tape row uses the same `TapeWriter`, so the digests are the stdio path's and call_proxy's: the call is opened when its POST is sent (a batch opens each call in order); the answer is read from a COPY of the response (JSON, JSON batch, or SSE `data:` events, including multi-line data and CR/LF/CRLF line ends; gzip/deflate decompressed for the copy only). A `202` leaves the call open for a later answer on another response in the same `Mcp-Session-Id` (the GET stream, the older HTTP+SSE transport); any other response without the answer, or an unreachable upstream (a plain `502`, never an invented JSON-RPC answer), closes it `unanswered` then. Calls still open at session end are `unanswered`, as on the pipe.
- Session brackets as on stdio: `session_begin` (transport `http-forward`, redacted `upstream`, `upstream_digest`, `listen`), `session_end` with `exchanges`, `upstream_errors`, `relay_errors`, `observe_failures`, `tape_calls`, `tape_failures`, and `tape_pin` when `--pin-witness` is set. `close()` waits (bounded, 5 s) for in-flight exchanges so an answer the agent already holds is on the tape before the session is closed behind it. A tape or observer failure is counted and never costs the call.
- `observer.py`: `SeamObserver(seam=...)` (rows say `mcp-http` in this mode); `observe_client_frame` returns the keys it opened and both observe methods take an optional `scope` (the session id); NEW `close_unanswered(keys, reason=)`. The stdio path passes none of these and is unchanged.
- NEW `test_http_forward.py` (25, written first and run red): JSON / sized SSE / chunked SSE answers taped with the stdio digests; byte-and-header fidelity against the upstream directly (JSON, batch, SSE, chunked, a 400, a non-MCP GET with binary bytes); batches in order; a 202 answered 0.5 s later on the GET stream; a 202 never answered; upstream down; non-MCP traffic untaped; a tape failure; brackets + strict verify; pin at session end; the CLI as a real process stopped by Ctrl+Break/SIGINT; three refused CLI shapes. Cross-repo, with no bridge: client -> adapter --http-forward (agent tape) -> tamper hop -> arcaeon-receipt call_proxy (tool tape) -> HTTP MCP server, reconciled with the ledger CLI: MATCHED 7 of 7 (JSON and SSE), ALTERED at 2, MISSING at 3 on the tool tape (skips with the reason when no tape-keeping call_proxy checkout is found; `$ARCAEON_RECEIPT_REPO`). Four break arms: a forwarder that reads no answers, an SSE parser that drops continuation lines, a forwarder that gives up on a 202, and a re-serializing forwarder, each caught.

- **Review fix (same branch): a lying Content-Length no longer hangs the agent.** When the upstream closed a sized body short of its own `Content-Length`, the forwarder had already promised the agent that length and kept the agent's connection alive, so the agent waited for bytes that would never come (8 s to its own timeout in the probe) where talking to the upstream directly gives the short body and EOF at once. Now the shortfall is counted in `relay_errors` and the agent's connection is closed, so it sees exactly what it would have seen directly (`IncompleteRead` with the same partial body). NEW test `test_a_content_length_that_lies_short_reaches_the_agent_short_and_closed` (red on the unfixed forwarder) with its break arm (`_upstream_short` forced False). NEW `test_duplicate_ids_in_a_batch_lose_no_call_from_the_tape` pins that three calls sent are three tape rows even with a duplicated id; which answer pairs with which duplicate is NOT claimed (see the review note: the pairing of duplicate ids is shared with the stdio path and disagrees with call_proxy's).

- **Cross-repo, the 202-answered-later case (same branch).** NEW `test_cross_repo_a_202_answered_later_matches_on_both_tapes`: client -> adapter --http-forward (agent tape) -> arcaeon-receipt call_proxy (tool tape) -> HTTP MCP server; a `tools/call` gets a 202, its answer arrives on the session's GET stream, and BOTH tapes close it with that answer: `MATCHED 2 of 2`. Against the slice-two call_proxy the tool tape said `unanswered` at call 1 (the disagreement this closes, fixed on the tool side in arcaeon-receipt `completeness-slice2` cae439e); the test SKIPs with the reason when the call_proxy found has no `KEEP_OPEN_STATUSES`. Break arm: a tool side that closes on a 202 fails it. Suite 197 passed with the fixed export.

### 2026-09-22 (branch completeness-slice2): pin the tape at session end

- NEW `--pin-witness URL` and `--tape-pair NS` (with `--tape`): when the session ends, after the tape is flushed, its head is pinned at the hosted witness through `arcaeon_ledger.tape_pin.pin_tape`, and the outcome rides in `session_end.tape_pin`. The key comes from `$ARCAEON_WITNESS_KEY`, never argv (argv is recorded in `session_begin`), and is never written anywhere. The pin record is also written to `<tape>.pin.json` for `arcaeon-ledger reconcile --pin`.
- NEVER fatal: no key, no arcaeon-ledger, a refused tape or a witness error is `could_not_pin` / `pin_refused` / `pin_failed` with the reason, and the proxy's exit code is the child's, unchanged. The seam and the tape are the product; the pin is the counter, and a counter that cannot be read is named, not faked.
- `tape.pin_at_session_end(...)` is the one call; it imports the ledger lazily, so the adapter still starts and records without it.
- Tests (in `test_tape.py`, +5, written before the code and run red): a real proxy session against a mock witness pins `rows=3` with `pair` and `record_format` sent and reported `dropped_by_witness`; no key; a 401; the library absent; and a break arm (a pinner one call short, planted in the subprocess) that the first test catches.

### 2026-09-22 (branch completeness-slice1): the tape, one side of "two tapes and a counter"

- NEW `arcaeon_adapter/tape.py` (`TapeWriter`, `request_digest`,
  `response_digest`): one `arcaeon-tape/1` row per `tools/call`. The call index
  is allocated when the request crosses this side, and rows are committed in
  index order, so row n is call n and a witness pin of `{rows, chain}` is a
  call counter. Digests are over content (`{name, arguments}`, `{result}` or
  `{error}`), so both sides compute the same digest for the same call and a
  different one when it changes in transit. `rpc_id` is recorded but kept out
  of the digests. A failed write leaves a visible gap rather than renumbering.
  Numbering resumes across restarts.
- `proxy.py`: `--tape PATH`, `--side agent|tool`, `--tape-namespace NS`. The
  tool side is the same binary wrapped around the server where it runs (one
  line of launch config). `session_begin` names the tape; `session_end` reports
  `tape_calls` and `tape_failures`.
- `observer.py`: `SeamObserver(tape=...)` feeds the tape. A tape failure is
  counted and never costs the seam row.
- NEW `test_tape.py` (11 tests) and `_tape_tamper_hop.py` (a test-only relay).
  The process tests run `client -> proxy(agent) -> hop -> proxy(tool) -> echo`
  and check four things: identical digests on both tapes when the hop is clean
  (`arcaeon_ledger.reconcile` says MATCHED 6 of 6); a different response digest
  at exactly the altered call (ALTERED at 2); MISSING at 3 on the tool side
  when the hop drops a request; and MATCHED through a byte-changing
  re-serialization. The reconcile assertions skip loudly on an arcaeon-ledger
  without `reconcile`.

## 0.1.4 — 2026-09-22 (SECURITY: spawn-failure path no longer echoes the unredacted command; README carries the MCP Registry marker)

**README carries the MCP Registry ownership marker (2026-09-22).** One HTML
comment, `<!-- mcp-name: io.arcaeon/adapter -->`, under the title. The official
MCP Registry proves a PyPI package belongs to a server name by fetching
`https://pypi.org/pypi/arcaeon-adapter/<version>/json` and looking for that token
in the description, per version. 0.1.3's README predates it, so 0.1.3 cannot be
listed; the next release can. Draft listing and submit runbook:
`registry/server.json`, `registry/REGISTRY_SUBMIT_2026-09-22.md`. Nothing
submitted.

**SECURITY: the spawn-failure path echoed the UNREDACTED launch command to
stderr.** `session_begin()` was already careful to log only `_redact_argv`'s
output, but the `cannot start server ...` line written straight to stderr when
the wrapped server failed to spawn used the ORIGINAL `command`. A command line
carrying a live credential (the whole reason the redactor exists) leaked it the
moment the server failed to start: the exact bug class 0.5.8 fixed for
`session_begin`, recurring on a path that fix never reached. Now `safe_command`.
Test in `test_proxy.py`. Found by the 2026-09-05 third-verdict code review
(internal board rows 204/205); in version control as of commit 97e014a, NOT yet
on PyPI (0.1.3 is current there). Ships as 0.1.4 in the next publish window.

**TESTS: the empty-log verdict shipped in 0.1.2 and 0.1.3 with nothing holding it.**
The 2026-08-28 `_ledger.py` fix (`verify_seam_log()`'s fallback stops returning
`ok=True` for a scan that walked zero rows, and now counts every break instead of
reporting only the first) was written in the standalone `arcaeon-adapter` checkout
and PORTED here as code. Its four regression tests were not. So the three-valued
verdict (`ok=True`/`"full"`, `ok=None`/`"empty"`, `ok=False`) has been live on PyPI
across two releases while no test in this tree so much as named `verified_scope`.
A package whose pitch is "a green you can trust" carried an untested green. The four
tests are now here verbatim: `test_empty_seam_log_is_not_a_green`,
`test_whitespace_only_seam_log_is_not_a_green`,
`test_fallback_counts_every_break_not_just_the_first`,
`test_a_good_log_reports_full_scope`. Suite 146 -> 150, all passing. No behavior
change; this only fastens what was already shipped. (2026-09-04, board item 54.)

## 0.1.3 — 2026-09-01 (sell-code audit: the proxy must not die on one bad ledger line; the redactor must not claim a secret it did not strip)

- `_ledger.py` (`_FallbackLedger._last_chain`, fallback `verify_seam_log`) and
  `observer.py` (`_parse`) caught `ValueError` on JSON but not `RecursionError`,
  which is what a deeply nested payload raises (~1000 levels on Python 3.11/3.12).
  The worst site was startup: one hostile line already in the seam log and
  `session_begin()` raised before the wrapped server ever spawned -- the exact
  failure this module's docstring says it must never cause. All three now treat
  the line as unparseable, the same as any other bad line; the verifier returns
  a break verdict rather than a traceback.
- `proxy.py` `_redact_argv`: `--auth oauth2` and `--auth client_credentials` were
  being replaced with the redaction marker and RECORDED as a stripped secret.
  Nothing was stripped; a mode word was. Third fabricated-redaction scar in this
  file. Fix is an explicit `_MODE_TOKENS` allowlist (oauth2, saml2, pkce, mtls,
  client_credentials, ...) checked before the shape heuristic; `--password hunter2`
  still redacts (a widened regex that let it through was tried and reverted --
  the test caught it).
- Tests: `test_ledger_binding`, `test_observer`, `test_redact_argv` each gain a
  planted red for the above. 146 pass.

## 0.1.2 — 2026-08-24 (SECURITY: ship the redactor fix that was already in version control before 0.1.1 uploaded)

The published 0.1.1 — itself a SECURITY release — leaked password-only URL
credentials: its `_URL_USERINFO` pattern required a non-empty username, so
`redis://:pass@host` and `mongodb://:pass@host` (the STANDARD shape for
both) passed through the redactor verbatim into `session_begin`, in the
default digest-only mode, in the file whose purpose is to be handed to an
auditor. The fix (`*` quantifier, commit aaeafdf in the development repo)
was committed roughly two hours BEFORE the 0.1.1 upload; the artifact was
built from a commit three earlier. A provenance vendor shipped a release
whose fix existed in its own history and not in its own bytes — found by
an independent adversarial audit of the published wheels, disclosed here
rather than smoothed over.

This release ships current HEAD, which also includes the redactor rewrite
0.1.1 was built before (f7492c5). 0.1.1 should be treated as leaking:
upgrade, and if a wrapped command line ever carried a password-only URL
under 0.1.0/0.1.1, rotate that credential — the seam log has it in
cleartext.

Known, disclosed, not fixed here (same audit): a hash chain cannot detect
truncation of its own TAIL — a chopped-off end verifies green; reconcile
`session_end.calls` vs the `tool_call` row count, check `seq` density, or
pin the head to an external witness (the README's honest-limit section now
needs this sentence; next release). The selftest's RED arms assert only
output-differs, so a crashed fault-run could masquerade as a caught
corruption (harness-only, not production-reachable).


## Shipped in 0.1.2 (entries below were written under an "Unreleased" heading that was not renamed at the 0.1.2 release; verified present in commit 434901c)

**HONESTY: the redactor was fabricating evidence, confirmed live by an independent
audit.** Four probes, all damaged with `command_redactions=1`: `--auth none` — a server
with authentication DISABLED, the exact scar class the 0.1.0 fix was named for —
recorded as credential-stripped; `--auth basic` and `--oauth google` lost their
mode/provider words the same way; `--authors Jane` lost a value because "auth" was
matched as a SUBSTRING of the name; and `pip install sk-learn-extras` lost a package
name to the `sk-` value shape. Three fixes, all in the direction the file's own doctrine
orders (fabricating a redaction is worse than missing one):

- Name words now match at separator boundaries only: `auth-token`, `API_TOKEN`, and
  `x-auth` still name secret slots; `--authors` and `--oauth` never did and now never
  match. `authorization` is spelled out since the boundary rule would otherwise drop it.
- A credential-NAMED flag no longer eats its following value unconditionally. A value
  that is a plain short dictionary word (`none`, `basic`, `google` — all-lowercase
  letters, ≤12 chars) survives, in both the two-token and `--auth=none` forms; anything
  secret-shaped or longer/mixed/digit-bearing is still redacted. The declared residual:
  a password that IS a short dictionary word in a named slot now survives into the
  record — the accepted direction of error.
- The `sk-` value shape now demands what every real issued key has — ≥20 chars plus a
  digit or mixed case — before redacting, so package names pass through untouched while
  `sk-proj-...` / `sk-ant-api03-...` keys still never reach the file.

All six probes are permanent MUST_NOT_TOUCH corpus cases (each observed red before the
fix), alongside three deliberately-green MUST_REDACT guards pinning the redactions the
fix was required to preserve (`--auth-token <secret>`, `--api-key=sk-ant-...`,
`API_TOKEN=ghp_...`). Corpus: 54 cases, 34 observed red.

**A second hardcoded version, found by the same audit.** `SeamObserver.__init__`
defaulted `impl` to a literal `"arcaeon-adapter/0.1.1"` — a copy
`test_version_is_declared_in_exactly_one_place` never saw, positioned to stamp stale
`seam_impl` values on rows after the next bump. The default now imports `IMPL` from
`_version.py`, and the test grew two teeth: the observer's stamped default must equal
the constant, and NO file in the package other than `_version.py` may contain a
version-shaped literal at all, so a future hardcode fails even while its value is
still current — which is exactly how this one stayed invisible.

**SECURITY: the redactor never checked the VALUE half of `NAME=VALUE` tokens against
the value-shape rules.** The whole-token `_SECRET_VALUE` match is anchored at the
token's start, so `STRIPE_KEY=sk_live_...`, `OPENAI_KEY=sk-proj-...`, `GH_PAT=ghp_...`
and a JWT in any innocently-named variable all passed through untouched with
`command_redactions=0` — the value-shape rule, the one defence that works when the
slot name says nothing, went blind exactly where secrets most often sit. The VALUE
half of every `NAME=VALUE` token is now run against the value shapes; only the value
half is replaced, and the hit is counted.

**SECURITY: `--key AIzaSy...` leaked.** Bare `key` was not a recognised slot name and
Google's `AIza` prefix was not a recognised value shape. Both added: `key` matches as
an EXACT name only (`--keyboard` and `MY_KEY` are untouched — substring-matching is
how `--no-auth` got eaten by "auth" in 0.1.0), and `AIza...` is now redacted wherever
it sits.

**Swallowed failures are now counted failures.** The relay swallows observer
exceptions by design (a logging bug must never break transport) and treats read/write
OSErrors as shutdown races. Both policies stand, but both were invisible: an observer
raising on every frame produced a `session_end` indistinguishable from a clean run,
while the equivalent gap from an oversized frame WAS reported. `session_end` now
carries `observe_failures` and `relay_errors` on the same contract as
`oversize_frames_unlogged`: omitted when zero, present when the record has a hole.
The client->server relay thread is also joined (bounded, 1s) before the counters are
read, closing the race where an increment landing a beat after child exit was lost.

**Test corpus hardened.** Redaction assertions now pin the literal placeholder string
instead of importing it from the module under test; a multi-secret case pins the exact
hit count; every MUST_REDACT case now also asserts the non-secret argv positions come
back byte-identical (a shredder mutant passed the old assertions and fails the new
ones — all three mutants were run and observed red); corpus cases added for all the
shapes above plus over-redaction guards (`MY_KEY=not-a-secret-word`,
`--keyboard=qwerty`, `COUNT=12345`).

## 0.1.1 — 2026-08-19 — SECURITY. Upgrade from 0.1.0.

Two defects, both breaking the one property this package
exists to provide: that everything crossing the instrumented seam is in the record.

**A tool call could be missing from the seam log while the chain still verified green.**
Certain content in a tool name — or, with `--raw`, in a tool's own response body — made
the row write fail. The proxy swallows observer errors by design, so that a logging
problem can never break a customer's transport, which meant the call executed, the
response was forwarded, and no row existed. Verification passed, because it checks that
the chain links hold and nothing checked whether a row was *absent*. The only residual
trace was a gap in the sequence numbers and a `session_end` whose call count disagreed
with the number of rows, and nothing in the package compared those two figures.

The consequence worth stating plainly, because it is the reason this is a security
release rather than a bug fix: **the party being audited could influence whether its own
call appeared in the record.** That is precisely what an out-of-process observer is for.

Fixed by making the FACT of a call non-negotiable while the fidelity of its text is not.
A row that cannot be written as-is is rewritten in a form that can be, and marked
`record_repair` so it declares its own alteration rather than passing as pristine. If
even that fails, a skeleton row records that an event occurred and that its content
could not be stored, because a row saying "something happened here and I could not keep
it" is worth incomparably more than a gap — a gap is indistinguishable from nothing
having happened. Only if all of that fails does it become a counted absence, reported as
`rows_unlogged` in `session_end`. **A hole in this log is now always a declared hole.**

**The wrapped server's command line was written verbatim into the `session_begin` row.**
This package is wired in by wrapping another server's launch command, and launch commands
routinely carry live credentials. That array was logged unconditionally, including in the
default digest-only mode that the documentation describes as person-free, into a file
whose stated purpose is to be copied into an evidence bundle and handed to a third-party
auditor. So the mode advertised as containing no sensitive payload was recording the one
string on the machine most likely to be a live key.

Command lines are now redacted before the row is built, with a `command_redactions` count
on the row so a clean command is distinguishable from a scrubbed one. `command_digest` is
still computed over the ORIGINAL argv, so the record continues to pin exactly what ran
for anyone who can supply the command and wants to check it; digesting the redacted form
would have been the quieter bug, pinning something that never executed.

**The redactor's limits, stated here rather than implied away.** It recognises a value
sitting in a credential-named flag, a value whose own shape is a known credential kind, a
credential inside a URL query string, and URL userinfo. It cannot recognise an
arbitrarily-named slot (`--k9 hunter2`), and it cannot recognise a bare high-entropy
value sitting in no slot at all with no known prefix.

**One distinction stated explicitly, because getting it wrong is how the first cut
leaked.** This function reads `argv` only. A secret passed through the actual process
environment is never seen by it and is never logged by this package either. But
`-e NAME=VALUE` is **argv, not the environment** — it is how `docker run`, `env`, and
most MCP client configs pass secrets, and it IS covered. An earlier draft of this note
said the redactor "does not read the environment" without drawing that line, which reads
as "that case is out of scope." It was not out of scope; it was the largest hole, and the
sentence pointed away from it. A limitation notice that misdirects is worse than none.

A redactor that quietly misses a class manufactures confidence, so the guidance is
unchanged and is the real control: **do not put secrets on a command line.** The
redaction is a second line, not a licence.

**Tests.** Both defects are covered by new tests, and each was verified to fail against
0.1.0 before the fix landed, because a regression test that has never been seen failing
proves nothing. Full suite: 111 passing.

**Reproductions are not published here.** Installs still on 0.1.0 are unpatched, and a
step-by-step method for removing a row from an audit log is useful to the wrong reader.
Ask if you have a concrete need for the detail.

Requires `arcaeon-ledger>=0.5.8` for the `[ledger]` extra: the library shipped matching
fixes in the same batch, including one where a log receiving writes that went nowhere
still reported as fully verified.

## 0.1.0 — 2026-08-19

First version. An MCP stdio proxy that records every tool call to a tamper-evident
ledger without the agent's cooperation.

### Why this exists

`arcaeon_ledger.Ledger.append()` records whatever a caller chooses to pass it.
That is a diary: an agent that skips the append leaves no trace, and one that
curates its appends leaves a flattering record. Any regime asking for *automatic*
recording (EU AI Act Art. 12(1) is the one on our desk) cannot be met by a library
the logged party calls voluntarily. MCP stdio is the seam where "no cooperation
required" is literally true — the client and server talk newline-delimited
JSON-RPC over a pipe, and a process sitting in that pipe sees everything at the
protocol level, in a process the agent does not own.

Design memo: `projects/online_business/ADAPTER_LAYER_DESIGN_2026-08-18.md`
(seam ranking, schema, pricing sketch, and the frozen honest-limit copy).

### Added

- **`arcaeon_adapter/proxy.py`** — the proxy.
  `python -m arcaeon_adapter --ledger PATH -- <server command...>`. Spawns the
  wrapped server, relays stdin→child and child→stdout byte-for-byte, logs the
  seam. Child's stderr is inherited (not piped); child's exit code is propagated.
- **`arcaeon_adapter/observer.py`** — non-destructive stream observation.
  `FrameSplitter` (chunk reassembly, unterminated final frame, bounded buffer with
  resync) and `SeamObserver` (request/response pairing by JSON-RPC `id`, row
  emission, session brackets).
- **`arcaeon_adapter/_ledger.py`** — ledger binding, with a byte-compatible
  fallback writer + verifier for machines without `arcaeon-ledger` installed.
- **`arcaeon_adapter/selftest.py`** — mutation harness. Five cases, each observed
  GREEN then forced RED on its own defect, with a no-op guard between.
- **`arcaeon_adapter/_echo_server.py`** — deterministic synthetic MCP server, so
  fidelity can be measured against an unproxied control run.
- **Row schema:** `tool_call`, `session_begin`, `session_end`, `mcp_initialize`,
  `tools_list`. Every row carries `seam="mcp-stdio"` + `seam_impl`, `session`,
  `seq`, `server`.
- **Flags:** `--ledger`, `--server`, `--session`, `--raw`, `--max-frame`.
- 65 pytest tests.

### Decisions, and what they cost

- **Digest-only by default; `--raw` opt-in.** Rows prove *which* bytes crossed
  the seam without warehousing them. Cost: you cannot reconstruct a payload from
  a row after the fact. That is the trade we want — an audit log that silently
  accumulates everyone's data is a liability, and person-free rows are far easier
  to retain for years.
- **Session is process-scoped, not `initialize`-scoped.** One proxy process = one
  session, and `session_begin` fires at start rather than at the MCP handshake. A
  begin row that waits for `initialize` does not exist when a client connects and
  dies, and then there is nothing for `session_end` to pair with. What the
  handshake tells us arrives separately as `mcp_initialize`.
- **`seam` is `"mcp-stdio"`.** The design memo sketched `"mcp-proxy/0.1"`, folding
  the tier and the version into one string. Split: `seam` names the *provenance
  tier* and must stay stable for a downstream verifier to switch on, while
  `seam_impl` carries the build. A tier identifier that changes every release is
  not a tier identifier.
- **An unanswered call is still rowed** (`status="unanswered"`, at shutdown).
  Without it, killing the server mid-call erases the fact that the call crossed
  the seam.
- **Oversized frames are counted and reported**, not silently skipped. A gap in
  the record has to be visible in the record.
- **`arcaeon-ledger` is not a hard dependency.** This gets wrapped around
  somebody else's working server by a config edit; a missing package must never be
  why their server fails to start. The fallback is byte-compatible and labelled in
  `ledger_backend`.
- **`.proxy` is imported lazily from `__init__`.** Not tidiness: importing it
  eagerly made runpy print a `RuntimeWarning` to stderr on every launch, and the
  proxy inherits the wrapped server's stderr. A logging sidecar that dirties the
  logs is a bad joke. Guarded by a test.

### Found while building

- The mutation harness's no-op guard fired twice, correctly, on mutations that
  proved nothing:
  1. The `reserialize` fidelity fault originally did `json.dumps(json.loads(f))`,
     which reproduced the echo server's own output byte-for-byte — a no-op. It now
     re-emits sorted + compact, which actually differs.
  2. The `one_row_per_call` mutation originally delivered every frame twice, and
     the row count did **not** change: popping the pending map makes the observer
     idempotent against duplicate delivery. Good property, useless mutation. The
     robustness is now its own test (`test_duplicate_response_delivery_does_not_
     double_row`) and the mutation is a log-as-you-see observer that really does
     break pairing.

  Both are the harness doing its job — a check that stays green on its own defect
  is decoration.

### Deliberately left for v1

- `--authority principal=...` — stamp `arcaeon_ledger.authority()` on every row.
- `--bind-inputs` — auto `bind_artefact` on input payloads.
- `--auto-pin N` — publish a head pin every N rows to a witness (this is the
  metered surface; the library itself stays free).
- Harness-hook recipe (`examples/claude_code_hooks/`) — catches built-ins the
  proxy is structurally blind to, at the cost of being per-harness config and
  cooperative-grade rather than infrastructure-grade.
- HTTP/gateway seam — the widest view of agent *intent*, and the most
  person-full; a hosted-tier feature, not a v0 move.
- Streamable-HTTP MCP transport. v0 is stdio only, which is the transport where
  a proxy is a config edit rather than a deployment.
- A `verify`-side reader that reports seam coverage across many session logs.
