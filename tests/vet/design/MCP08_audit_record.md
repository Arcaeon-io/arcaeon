# MCP08 — `audit-record`: does a tool call leave a verifiable record?

_Design note, 2026-08-30. Board item B2. Research: `projects/online_business/BATCH100_R_OWASP_MCP08_2026-08-30.md`._

## Why this class and not another

Every other check in `mcp_vet` asks **"can this server be made to do something
dangerous."** MCP01 (`secret-in-code`) asks **"is it leaking at rest."** This one
asks a third question: **"if it did something, could anyone prove what."**

That question is the wedge. From the research pass:

- OWASP MCP08 ("Lack of Audit and Telemetry") mandates structured per-call
  records (timestamp, agent/session id, tool invoked, parameters, result,
  identity), **cryptographic hashing (HMAC/SHA-256) over the log**, **append-only
  or write-once media**, and periodic drills proving an investigator can
  reconstruct events.
- Snyk Agent Scan's ~21 issue codes (E001–E006, W001–W021) contain **zero**
  audit/telemetry checks. They own tool-description poisoning, prompt injection,
  skill malware and secret handling. Nobody tests the audit-trail control.
- The reason nobody tests it is that MCP08 is about a **control being present**,
  not a **bug being absent** — which is awkward for a vulnerability scanner and
  natural for a grade.

So: `audit-record` is the first check in this tool that can come back **clean as
a compliment** rather than clean as an absence of evidence.

## The 4 gates (from the research doc, §2)

| Gate | Question | Static evidence we accept |
|---|---|---|
| 1. **presence** | does a tool call produce a record at all? | a logging call **naming the tool**, an append-mode file write, a DB `INSERT`, a ledger-style `append`, an OpenTelemetry span — reached from a tool handler or a `tools/call` dispatcher in <= 2 hops |
| 2. **completeness** | does the record carry tool name + timestamp + args/digest? | those three as dict keys / kwarg names / assignment targets in the record-writing function, or as words in the log format string; timestamps also from `time.time()` / `datetime.now()` / `.isoformat()` |
| 3. **tamper-evidence** | is a silent edit detectable? | a ledger/append-only library import, `hmac`, a `chain`/`prev_hash`/`head_hash`/`signature` field, or a SHA-2 call in a function that also names `prev`/`head`/`last`/`link` |
| 4. **reconstructability** | can an independent party replay it? | a `verify*` / `replay*` / `reconstruct*` function defined or called |

**One finding per server**, severity = the first unmet gate:

| first unmet | severity | reading |
|---|---|---|
| presence | **high** | a tool call leaves nothing behind |
| completeness | **medium** | something is written but it is not an audit record |
| tamper-evidence | **medium** | a plain, rewritable log |
| reconstructability | **low** | chained, but nobody can replay it |
| — | *no finding* | all four gates met |

The finding carries a `gates` dict so a reader sees the whole ladder, not just
the rung that failed.

## Precision rules (the whole game, same as MCP01)

- **`print()` is never a record.** Not a sink, not a field, not evidence.
- **`logging.info("done")` is not a record.** A logging call only counts as
  presence if it names the tool — the tool-name field, or the handler's own
  name. A log line that cannot tell you *which tool ran* cannot answer the
  question MCP08 asks.
- **The check only runs on a file that is actually a server**: at least one
  decorator-registered handler or a `tools/call` dispatcher, **and** an
  entrypoint (`run()`/`serve()`/`main()`/`if __name__ == "__main__"`). Asking a
  fragment of a module where its audit trail is, is noise. This is a real
  narrowing and it is confessed as a gap, not hidden.
- **Everything is AST**, never a text scan over the source. The `zero-auth`
  check's whole-file substring test is our own worst blind spot — the word
  *author* in a docstring silences it. `mcp_vet/server.py` mentions
  `mcp_vet.grade.verify()` inside a tool description string; a text scan would
  hand it gate 4 for a sentence. Gate 4 requires a real `FunctionDef` or `Call`.
- **An append-mode `open()` alone is NOT tamper-evidence.** The research doc
  lists "append-only or write-once media" under gate 3, but a plain `open(p,"a")`
  is one `w` away from a rewrite and statically indistinguishable from WORM
  storage. Counting it would let "plain unchained log" pass gate 3, which
  contradicts the severity ladder. Append-mode counts for **presence** only.
- **Gate 2 wants field names, not vibes.** `"op"`, `"action"`, `"method"` and
  `"name"` are deliberately NOT accepted as the tool-name field, even though a
  dispatcher's `name` variable usually *is* the tool name. Too many records use
  those keys for something else.

## What this cannot see (confessed, evidenced in `grade.py`)

- A record written by **middleware or an imported decorator** outside the file.
  The server is audited; we call it high. **False red, and the worst direction
  of error this tool has** — filed with a fixture that fires.
- A sink whose durability lives in **configuration** — syslog, journald, a WORM
  bucket, a managed OTel collector. We can see the write; we cannot see where it
  lands, so we call a real append-only pipeline "unchained."
- **Partial coverage.** Gates are evaluated per file, so a server that records
  one of its five tools passes gate 1.
- **Gate 3 is a file-level smell**, not proof the chain covers the audit record.
  A server that hash-chains something unrelated gets the gate.
- Handlers and entrypoint in **different files** — never asked the question.
- **A record behind an optional import** (`try: import ledger / except ImportError`).
  The write is in the source so every gate passes, but whether it ever RUNS is
  decided at install time. Found 2026-08-30 on our own fix (v0.0.7, board B2b):
  `mcp_vet/server.py`'s trail needs the `[audit]` extra and scores clean either
  way. Filed as a miss with a fixture pair (`grade.py: _BS_MCP08_OPTIONAL`).
  Detecting the guard is probably the wrong fix — a guarded optional sink is a
  legitimate shape, so the honest correction is a gate downgrade, not a new
  pattern match. Open.

## What passing looks like, on our own code (v0.0.7)

The reference implementation of this control is now `mcp_vet/server.py` itself,
which scored **high** on this check for the whole of v0.0.6:

| gate | what makes it true |
|---|---|
| 1 presence | `ledger.append(record)` inside `_record_call`, one hop from each handler |
| 2 completeness | `tool`, `ts` (ISO-8601 UTC), `args`, plus `source_sha256` of the bytes read |
| 3 tamper-evidence | the `arcaeon_ledger` import — append-only, hash-chained per row |
| 4 reconstructability | `verify_audit_ledger()`, exposed as an MCP tool and as `mcp-vet audit-verify` |

Three of those four are cheap to fake in source, which is why the fix carries
runtime tests for all four (`test_audit_ledger.py`) — one row per call through a
real client, and a tampered row named by line number. A static gate that a
project can satisfy by rewording itself is a grade nobody should buy.
