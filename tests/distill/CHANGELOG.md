# Changelog — arcaeon-distill

## 0.1.7 — 2026-09-02 (the MCP server leaves its own call record)

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
  first in the registry-benchmark queue with the other four of ours, graded
  `mcp_server.py` gate 0 of 4: a `tools/call` left nothing behind on any
  tool-handling path. Now every `tools/call`, success or refusal, appends one
  hash-chained row to `$ARCAEON_CALL_RECORD` (default
  `./distill.calls.jsonl`): tool name, the server's own UTC timestamp, sha256
  of the canonical arguments (always), the arguments inline under 4 KB,
  outcome, and the error text on a refused call. The row is written AFTER
  the tool runs so it carries the outcome; a call whose record cannot be
  written is answered as an error, never as if it had been logged.
  `python -m arcaeon_distill.mcp_server --verify-calls [path]` walks the
  chain and exits 1 on a break.
- **`arcaeon_distill/_ledger.py`**, stdlib only, so the zero-dependency
  pitch stands. It writes the SAME chain format as arcaeon-ledger
  (`sha256(prev + json.dumps(row minus chain, sort_keys=True))[:32]`, genesis
  `"genesis"`), and the suite proves it: a record written here verifies under
  `arcaeon_ledger.verify_file` when that package is present (test skips
  cleanly when it is not). One record format across our five servers, not a
  fork of one.

### Measured

- mcp-vet grade of `mcp_server.py` before: gate 0 (no record). After: gate 4
  (record present, complete, chained, replayable). Mutant check: deleting the
  single `_record_call(...)` line drops it back to gate 0, so the grade is
  tracking the record and not the imports. Two honest notes on that grade:
  mcp-vet awards tamper-evidence on the ledger-module import, the same rule
  any stranger importing a ledger library gets; and mcp-vet grades one file
  at a time, so a first cut with the row built in a helper module graded
  gate 1 despite writing an identical record. The fix is not a rename: the
  row's fields now live beside the handler that produces them, which is
  where a reader looks for them anyway. The cross-file blindness is filed
  against mcp-vet, not papered over here.

### Limits stated

- Single-writer. A stdio MCP server is one process; this record does not
  take the cross-process lock the full ledger does. Two servers pointed at
  one file can fork the chain, and `--verify-calls` will then say so.
- The record proves the server said what it did. It does not prove the
  distill was correct; that is what the drop receipt and the golden
  fixtures are for.

Suite 62 -> 66.

## 0.1.6 — 2026-09-01 (sell-code audit: crashes where the contract promised a refusal)

An audit hunting inputs a normal caller can hand this package that escape as
a raw crash rather than the typed refusal the docstrings promise, plus a
README claim wider than the code. Five findings, all fixed, each with a
regression test watched failing on the 0.1.5 source first (5 failed there,
all pass here). No golden fixture changed: every fix is in a refusal path or
a verifier, never in what an admitted input distills to. Suite 57 -> 62.

### Fixed

- **The MCP server died on one non-object JSON-RPC line.** `handle()` called
  `msg.get(...)` on whatever `json.loads` returned, so a client sending
  `[1,2]`, `"x"`, `123` or `null` killed the process with an AttributeError
  (measured: `printf '[1,2]\n{...tools/list...}' | python -m
  arcaeon_distill.mcp_server` -> traceback, and the valid `tools/list` after
  it was never answered). Same for `"params": [1]`, which reached
  `params.get` outside the try/except that promises to "never crash the
  server on one bad call". Non-object messages are now ignored like a
  notification (they carry no id to answer); a non-object `params` gets the
  JSON-RPC `-32602` invalid-params error. Test:
  `test_mcp_server_survives_non_object_jsonrpc_lines` (function-level and
  end-to-end over stdio).

- **`verify_receipt()` raised instead of saying "malformed".** It is the
  function a caller points at a receipt it did not mint, and `{"full": "x"}`,
  `"drops": "nope"`, `"drops": ["x"]`, `"distilled": null` or a receipt that
  is a list all escaped as AttributeError/TypeError from `.get`/`dict()`. The
  docstring's `"malformed"` scope now covers wrong SHAPES, not just missing
  keys, and the function never raises on a bad receipt. Test:
  `test_verify_receipt_fails_safe_on_malformed_shapes_instead_of_raising`.

- **Lone surrogates: receipt=True crashed, receipt=False shrugged.** A str
  that cannot be UTF-8 encoded (`surrogateescape` output from a subprocess,
  or the JSON escape for U+D800 inside JSON text) has no byte serialization.
  With a receipt the digest step died deep inside `.encode()` with a
  UnicodeEncodeError; without one the string came back as content as if
  nothing were wrong. The admission walker now refuses it at the door, naming
  the path, for values, dict keys and JSON-text escapes alike. Test:
  `test_lone_surrogates_are_refused_at_the_door_for_every_input_form`.

- **NaN/Infinity arriving as JSON text bypassed the door.** `json.loads`
  accepts the `NaN`/`Infinity` tokens, and the admission walker only ever saw
  the raw string, so `distill('{"x": NaN}')` surfaced as json.dumps's own
  "Out of range float values" error from inside a strategy, with no path.
  The parsed value now takes the same admission check as a Python object
  (skipped when they are the same object, so no double walk on the common
  path). Test:
  `test_nan_inside_json_text_gets_the_same_typed_refusal_as_a_python_nan`.

- **Pathological nesting escaped as a raw RecursionError.** `json.loads`,
  `_walk_json` and `json.dumps` are all recursive; a value or JSON text
  nested 5000 deep blew the recursion limit uncaught (measured on 3.14: depth
  990 fine, 3000 not). It is now a `ValueError` like every other refused
  input. The depth that trips it still depends on `sys.getrecursionlimit()`
  and the caller's own stack; the message says so. No fixed depth cap was
  added, so nothing that distilled before is refused now. Test:
  `test_pathological_nesting_is_a_typed_refusal_not_a_recursion_error`.

- **"Tamper-evidently honest" claimed more than an unsealed receipt is.** The
  module docstring and the README both said the receipt is tamper-evident;
  an unsealed receipt is a plain dict and `verify_receipt()` checks shape,
  not provenance (its own `verified_scope` says so). Both now say the receipt
  is honest about the loss and becomes tamper-evident once `seal()`ed onto a
  ledger. Wording only.

### Checked and clean

Empty str/bytes/list/dict, whitespace-only text, JSON scalars under
`schema_hint="json"`, non-UTF-8 bytes (typed refusal, unchanged), a 1 MB
single-sentence string (returns whole, `truncated=False`, over budget: the
README's disclosed non-proof 3, not a defect), 20k-row tabular input, tuple
top-level input (admitted by the walker, refused typed by strategy
detection: inconsistent wording, same exception class, left alone). No file
I/O, deserialization, `eval`/`exec` or secrets anywhere in the package.
Versions agree: `__version__`, `pyproject.toml`, the MCP `initialize`
response, this header.

### Known, not fixed

`python test_distill.py` (the manual runner, as opposed to `pytest`) reports
39/40 because `test_seal_reports_honestly_whether_or_not_the_ledger_is_installed`
takes the pytest `tmp_path` fixture and the manual runner cannot supply it.
Pre-existing, cosmetic, pytest is the documented runner.

## 0.1.5 — 2026-08-28 (external audit: greens that had not earned their scope)

An audit hunting one defect class — *checks that report clean without having
run* — against this package. Four findings, all fixed, each with a test watched
failing first.

### Fixed

- **`_well_formed()` validated colon count, not the digest it named.** It ended
  in `int(parts[3], 16)`, and `int()` is a number parser, not a hex-string
  validator: it accepts `0x` prefixes, `+`/`-` signs, `_` digit separators,
  surrounding whitespace, and Unicode decimal digits. Measured accepts before
  the fix: `x:y:z:5`, `md5:lol:v9:deadbeef`, `sha256:raw-bytes:v1:0xFF`,
  `sha256:raw-bytes:v1:-ff`, `sha256:raw-bytes:v1:f_f`, `sha256:raw-bytes:v1: ff `.
  There was no check on algorithm, recipe, or hex LENGTH — a sha256 body is
  always 64 characters. So the note emitted on failure ("is not a well-formed
  self-describing digest") claimed a property the code never tested, and a
  forged receipt with correctly-punctuated garbage passed structural review.
  Now pinned to `sha256` + exactly 64 lowercase hex characters, the only two
  shapes this package emits. **The failing branch was also dead:** the one test
  that claimed to cover it used `"not-a-real-digest"`, which has zero colons
  and never reached the hex check.

- **`verify_receipt()` returned a bare `ok: True` for a check that never touched
  content.** A receipt with a made-up strategy, a negative budget and three
  fabricated digests came back `{"ok": True, "notes": ["self-consistent"]}`.
  The docstring always disclosed the limit; the RETURN VALUE did not, and `ok`
  is what callers branch on. Every return path now carries **`verified_scope`**
  (`"structural_only"` / `"unknown_schema"` / `"malformed"`), and a structural
  pass says in its notes that it does not re-derive drops or bind any digest to
  content. **This is an ADDITIVE key on a public return value** — existing
  `result["ok"]` / `result["notes"]` reads are unchanged. `ok` semantics are
  deliberately NOT changed here; see "Flagged, not changed" below.

- **`test_seal_without_ledger_raises_clear_error` could not fail, and wrote a
  real ledger into the repo root on every run.** `"nonexistent.jsonl"` was
  passed as if the name were a sentinel meaning "this path does not exist". It
  is a live relative path resolved against pytest's cwd. With `arcaeon-ledger`
  installed the `except ImportError` never fired, the test fell through to an
  unconditional PASS print having asserted nothing about the branch that ran,
  and `seal()` appended a hash-chained row to `./nonexistent.jsonl` and
  `os.open`'d `./nonexistent.jsonl.lock` every time. The jsonl reached 38 KB
  across ~60 runs. Renamed to
  `test_seal_reports_honestly_whether_or_not_the_ledger_is_installed`, moved to
  `tmp_path`, and both branches now assert. **The zero-byte
  `nonexistent.jsonl.lock` was git-tracked (added in the 0.1.4 release commit)
  and SHIPPED INSIDE the 0.1.4 sdist** — `.gitignore` had `*.jsonl`, which does
  not match `.jsonl.lock`. File removed from the index and `*.lock` ignored.

- **`test_estimate_tokens_heuristic` sampled only coincidence points.** Found by
  mutation: changing the ~4-chars-per-token divisor from 4 to 3 left the whole
  57-test suite green. Every input the test chose gives the same answer under
  both constants (`4 // 4 == 4 // 3 == 1`; `8 // 4 == 8 // 3 == 2`), so the
  assertions could not discriminate the constant they existed to pin. Added
  discriminating points (`12`, `40`, and the README's documented
  `estimate_tokens("some text") == 2`) plus a round-trip against `_char_budget`,
  which carries the same constant in the opposite direction. The mutation is
  now caught.

### Added

- Anti-vacuity guard on the golden fixtures: `test_golden_fixture_set_is_never_
  silently_empty`. Both golden tests are bare `for case in ...` loops that print
  an affirmative PASS; with `cases` emptied they pass in under a second and
  announce that zero cases matched, turning the package's only cross-version
  guarantee into a no-op that reports success. Verified: with `cases` emptied,
  the three pre-existing golden/determinism tests still passed and only the new
  guard failed.

### Flagged, not changed (needs a deliberate call)

- `verify_receipt()` still returns `ok=True` for a structural-only pass, and
  `ok=False` for both "I found a fault" and "I could not check" (unknown schema
  / malformed receipt). `arcaeon-ledger` 0.6.0's three-valued contract would
  make the first `ok=None` + a bounded scope, and separate "unverifiable" from
  "faulty". That is a breaking semantic change on a published API, so it is
  recorded here rather than made silently. `verified_scope` above is the
  non-breaking half of it.

## 0.1.4 — 2026-08-24 (D-1/D-2 from the sealed verdict-field audit, disclosed before fixed)

Both findings were published in the 8/24 reciprocal-audit reconciliation
(Colony, ColonistOne thread) as "not yet fixed; disclosed rather than held
back" — this release closes them the same day.

- **D-1** — `verify_receipt`'s docstring always claimed "non-negative
  counts" are checked; the loop only ever validated `dropped_bytes`. A
  receipt with `dropped_count` negative, a string, a bool, or absent
  entirely still stamped "self-consistent" — the claimed predicate
  exceeded the delivered one on the package's own honesty hook, which is
  the exact class the sealed criteria audit hunts. Now every drop's
  `dropped_count` must be a non-negative non-bool integer.
- **D-2** — the tabular TEXT path stripped leading/trailing newlines from
  the input and never restored them: content dropped from the output with
  no `drops[]` row and `truncated: False`, in the package whose entire
  contract is that every dropped byte is receipted. The newline affixes
  are now preserved on every return path (they also count toward the
  budget check, since they are part of the returned string).
- Both mutation-verified: each fix reverted, its planted red confirmed
  failing on the exact old behavior, restored. Suite 37 → 40.
- Also: `__version__` is now test-pinned to pyproject.toml's version (the
  two-place version gap found in three sibling packages this morning).

## 0.1.3 — 2026-08-16

Hypothesis property-test pass, same night as `arcaeon-continuity` and
`arcaeon-ledger` (ledger found a real `splitlines()`-vs-`ensure_ascii=False`
false-mismatch bug on the U+0085/U+2028/U+2029 unicode-line-separator class).
**Verdict for this package: that specific bug class is ABSENT.**
`arcaeon_distill` never writes a JSONL file and reads it back itself — the
digest functions use `ensure_ascii=False` but only ever feed `hashlib.sha256`,
and the text/tabular strategies already split on literal `"\n"`, not
`.splitlines()`. The one place this package DOES touch a real write-then-
read-back JSONL path is `DropReceipt.seal()` → `arcaeon_ledger.Ledger`, which
is covered end-to-end by a new integration property test
(`test_line_separator_class_survives_seal_and_ledger_readback`) and passes
against the already-fixed ledger 0.5.6.

Three real bugs turned up this pass and were fixed:

- **Fixed (H-int-1) — `DropReceipt.seal()` returned a receipt that silently
  diverged from what actually got chained.** `seal()` handed its row to
  `arcaeon_ledger.Ledger.append()`, which copies its input and
  `setdefault`-stamps `ts` on that COPY — so the dict `seal()` returned to
  the caller never had `ts` set, while the chained row did. A caller who
  re-hashed the receipt `seal()` gave them (the documented, honest way to
  verify their own copy) got a hash mismatch against the published chain —
  a false integrity failure with no tampering involved. Fixed by
  pre-stamping `ts` (same `"%Y-%m-%dT%H:%M:%SZ"` format as
  `arcaeon_ledger._now_iso()`) before calling `append()`, so `append()`'s
  `setdefault` becomes a no-op and the row `seal()` returns is now
  byte-identical to the row that was chained. Mirrors the identical fix
  already applied to `arcaeon_compact`'s `seal()` the same night.

- **Fixed (H-distill-1) — `distill(bytes_input, ...)` always raised, contradicting
  the documented contract.** The module docstring's Args section and
  `_reject_undistillable` both promise/admit raw `bytes` as a valid top-level
  input (`_digest_value` even has a dedicated bytes branch), but
  `_detect_strategy` had no bytes case and fell through to the generic
  `TypeError`. Fixed by decoding bytes to UTF-8 str up front in
  `_detect_strategy`, so bytes now flow through the same auto-detection (and
  `schema_hint`) logic as an equivalent str. Non-UTF-8 bytes raise a clear
  `ValueError` instead of a confusing downstream `TypeError`.

- **Fixed (H-distill-2) — the json-strategy shrink loop could make output
  LARGER than the input while reporting `truncated=True`.** With a budget too
  small to ever be reached (e.g. `budget=1` → 4 chars), the loop drives
  `list_cap`/`dict_cap` down to their floor (2 / 4) regardless of whether the
  container needed cutting at all. A 3-item list of empty lists (12 chars)
  got floor-capped to 2 items, inserting a `"...+1 more items"` marker (17
  chars) that is itself longer than the one item it replaced — net output
  grew from 12 to 28 chars while `truncated=True` claimed a cut helped.
  Found by `test_distill_content_is_a_json_fixpoint`. Fixed by tracking the
  smallest-size iteration seen across the shrink loop instead of
  unconditionally returning the last one; every iteration is an internally
  consistent candidate, so this is always at least as good and is a no-op on
  every case that already reaches budget (confirmed: all golden vectors in
  `selftest.py` unchanged; see the full test count below).

Also added, from the same mutation-testing pass, four boundary-condition
regression tests that caught surviving off-by-one mutants without finding a
live bug: a dict/list/string at exactly its default cap must round-trip
untruncated (`>` vs `>=` on the cap check), and a 2-row list-of-dicts — the
smallest valid input — must still auto-detect as the `tabular` strategy.

Test count: **32 → 51 passed** (37 in `test_distill.py` + 14 in
`test_hypothesis_distill.py`; all pre-existing tests still pass unmodified).

## 0.1.2 — 2026-08-15

Fixes from the 2026-08-15 adversarial scrutiny pass
(`projects/online_business/SCRUTINY_DISTILL_2026-08-15.md` in the private monorepo).

- **Fixed (H2) — shared references were falsely refused as reference cycles.**
  `_reject_undistillable`'s admission walker tracked one global `seen` set of
  `id(v)` that was never popped on backtrack, so any value referenced twice
  (`x = [1,2,3]; {"a": x, "b": x}` — a legal DAG, `json.dumps` handles it
  fine) was refused with the message "input contains a reference cycle,"
  which was false. Rewrote the walker to track per-branch ancestors
  (`on_path`, popped via an explicit `_EXIT_MARKER` frame when a container's
  subtree finishes) separately from already-cleared shared subgraphs
  (`cleared`, skipped rather than re-walked). A true cycle — direct
  (`x.append(x)`) or indirect (`a["b"]=b; b["a"]=a`) — is still refused.
  Regression: `test_shared_reference_is_accepted_not_rejected_as_cycle`,
  `test_true_reference_cycle_is_still_rejected`.

- **Fixed (M1) — the json strategy never capped dict breadth; a wide dict
  blew the budget ~194x with `truncated=False`.** `_walk_json` capped string
  length and list length but had no dict-key cap, so a 5000-key dict at
  budget=100 (char_budget=400) landed at 19,445 chars — honest
  (`truncated=False`, nothing was cut) but misleading, since the README's
  disclosed over-budget exceptions didn't name this ordinary shape (a config,
  an id→status map, an embeddings dict). Added a `dict_cap` (default 200,
  floor 4) that shrinks alongside `str_cap`/`list_cap` in the same bounded
  shrink loop; a wide dict now keeps a head/tail slice of keys with a
  `__distilled_dropped_keys__` count marker and a `dict_truncated` drop entry,
  same pattern as `list_truncated`. The reproduction case now lands at 363–414
  chars against the 400-char budget (was 194.4x over) with `truncated=True`.
  Regression: `test_wide_dict_budget_is_enforced`.

- **Fixed (L1) — README/docstring "Every key is kept" overstated.** Reworded
  to "every key of a *retained* value is kept" in both the module docstring
  and README — a dict/list element cut whole by list or dict truncation takes
  its keys with it; that was always true and is now stated correctly.

- No schema change: `DropReceipt`/`verify_receipt` shape is unchanged, just a
  new `"dict_truncated"` value in the existing `drops[].kind` enum. Golden
  cross-version fixtures (`golden_fixtures.json`, frozen at 0.1.0) and
  selftest golden digest vectors are unaffected — none of the frozen inputs
  are wide enough to trigger the new dict cap (max dict width 4, cap default
  200) or share references. Full suite: 32/32 (`test_distill.py`), selftest
  `ALL PASSED`.

## 0.1.1 and earlier

Pre-CHANGELOG history. See git log and the 2026-08-14 audit for the
`schema_hint='tabular'` on a dict fix and the H1 receipt-privacy README/
docstring correction.
