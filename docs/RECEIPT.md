# Receipts

`arcaeon.record.receipt` issues one receipt shape for several uses. Every
receipt is built by `core.build_receipt`: a body, a body digest, one row in a
hash-chained ledger, an optional witness pin of the ledger head, and an
optional OpenTimestamps anchor. Each sub-feature below owns two things: what
its checks look like, and the scope block printed on the receipt (`proves`
and `does_not_prove`). `build_receipt` refuses a scope without both lists.

This page covers six sub-features: approval, authorship, ballot, cite,
call_proxy and archive. Every flag below is quoted from the argparse
definition in the module named beside it.

## How you reach them

Only some of them are on the `arcaeon` command line.

| sub-feature | `arcaeon receipt` subcommand | other entry point |
|---|---|---|
| cite | `cite` | `python -m arcaeon.record.receipt.cite_mcp` (MCP server) |
| ballot | `ballot` | none |
| archive | `archive` (and `roster-report`, which it builds on) | none |
| approval | none | `python -m arcaeon.record.receipt.approval_mcp` (MCP server); library `approval.ApprovalGate`, `approval.artifact_approval_receipt` |
| authorship | none | `python -m arcaeon.record.receipt.authorship_ingest`; `python -m arcaeon.record.receipt.authorship_mcp` (MCP server); library `authorship.AuthorshipSession` |
| call_proxy | none | `python -m arcaeon.record.receipt.call_proxy`; the one-call form is `python -m arcaeon.record.receipt.call_mcp` (MCP server) and library `call.call_receipt` |

`arcaeon receipt` also has `verify` and `exhibit`, which work on a receipt
of any kind.

The MCP servers speak JSON-RPC 2.0 over stdio (`initialize`, `tools/list`,
`tools/call`). They are not the `arcaeon mcp` server.

## Exit codes

Through `arcaeon receipt`, the module's own codes are translated by
`arcaeon.verdict.LEGACY["receipt"]`:

| module code | meaning in the module | `arcaeon receipt` exits |
|---|---|---|
| 0 | ok | 0 |
| 1 | usage or transport error (a file that cannot be read, a missing token, a bad roster) | 1 |
| 2 | verify failed (`verify`), or a FAIL inside (`--batch`, `roster-report`, `archive`) | 1 |
| 3 | `cite`: a flagged citation | 1 |
| 4 | `--batch`, `roster-report`, `archive`: nothing BROKEN, but COULD NOT LOOK at one or more receipts | 3 |

An argparse usage error exits 2 and is not translated. `--legacy-exit`
returns the module's own code. Note that the module's own 1 passes through
as 1, so through the front door a 1 can be a bad finding or an error the
subcommand hit before it could check anything; the stderr line starting
`error:` tells them apart.

The `python -m` entry points are not translated; their codes are listed in
each section.

## Verdict words

A single `arcaeon receipt verify r.json` prints `core.verify_receipt`'s
JSON. `ok` is true only when the body digest recomputes, the ledger status
is `not_checked` or `consistent`, an anchor that was asked for is proven,
the file has no duplicate keys, the witness block is not inconsistent, and
the attestation signature (if any) belongs to the receipt.

`verify --batch`, `roster-report` and `archive` print one word per
receipt, from `verify_batch.SAY`: VERIFIED (machine value `ok`), BROKEN
(`FAIL`) and COULD NOT LOOK (`undetermined`). The machine values are what
the JSON, the roster CSV and the archive manifest carry.

Each sub-feature also has words of its own on its check rows, listed in its
section. Those are fields of the receipt, not verify verdicts.

## approval

Module: `approval.py`, `approval_mcp.py`. Receipt kind `human-approval`.

What it does. `ApprovalGate` writes three ledger rows in order:
`approval_proposed` (the sha256 of the action's canonical JSON),
`approval_decided` (principal, decision, bound to the proposal), and
`approval_executed` (the digest of what actually ran). `decide` accepts
only `approved` or `denied` and refuses an empty principal (error prefixes
`bad_decision:` and `empty_principal:`). `executed(proposal, None)` means
the action did not run. The receipt's one field that answers the auditor
is `executed_as_approved`: true when an approved action ran with the same
digest, or a denied action did not run. Anything else sets
`executed_as_approved` false and the check `flagged` true.

Exhibit words: `AS APPROVED` or `!! MISMATCH`, then `ran` or
`did not run`.

The MCP server (`approval_mcp`) never decides. Tools: `approval_propose`,
`approval_status`, `approval_executed`, `approval_list_pending`.
`approval_executed` is refused while the proposal is pending. A decision
arrives as a file `<decisions-dir>/<proposal_id>.json` holding `principal`,
`decision` and `note`. The server reads pending decision files at the start
of `approval_status`, `approval_executed` and `approval_list_pending`; it
has no watcher thread. A file it can apply moves to
`<decisions-dir>/applied/`; one it cannot (empty principal, unknown id, a
decision that is not `approved` or `denied`, a proposal already decided,
invalid JSON) moves to `<decisions-dir>/rejected/`. Proposal state is kept
in `--state` and survives a restart. Receipts from this server are issued
with the witness pin on and the anchor off.

Flags (`approval_mcp.main`): `--ledger` (default `approval.log.jsonl`),
`--decisions-dir` (default `decisions`), `--receipts-dir` (default
`receipts`), `--state` (default `approval_state.json`), `--agent`.

Artifact approval. `artifact_approval_receipt(artifact_hash, approver_id,
approval_text, ledger_path=...)` is a one-shot sign-off, kind
`artifact-approval`. It records the artifact hash the caller computed, the
approver id, the timestamp and the sha256 of the approval text; neither the
artifact nor the text is stored. It has no CLI and no MCP tool.

What it does NOT prove (from `approval.SCOPE`):

- That the principal is a human, read the action, or had authority to
  approve it. The principal is asserted data, not a signature.
- That nothing else ran: only actions routed through this gate are
  recorded.
- That the action was wise, safe or compliant.

For the artifact form (`approval.ARTIFACT_SCOPE`): not that the approver
had authority, not that they were competent to judge it, not that the
artifact is good. Its `proves` line says the approver's "credential
signed" the hash; the function computes no signature. It records the
approver id beside the hashes, so the id is asserted the same way the
principal is above.

## authorship

Module: `authorship.py`, `authorship_ingest.py`, `authorship_mcp.py`.
Receipt kind `authorship-process`.

What it does. `AuthorshipSession` takes edit events with `op` one of
`type`, `paste`, `delete`, `idle`. Each event is folded into a rolling
sha256 as it arrives. Span text is digested and never stored. Every 500
events (`CHECKPOINT_EVERY`) and at close, the rolling hash is checkpointed
into the ledger. `close(final_text)` binds the final text's sha256 and
issues the receipt with `typed_chars`, `pasted_chars`, `paste_events`,
`deleted_chars`, `pasted_share` and the checkpoints. `replay(events)`
recomputes the rolling hash from a saved event list, so someone with the
events and the receipt can check it without the issuer. The receipt draws
no conclusion about who wrote the text.

`authorship_ingest` turns an export from `web/authorship-recorder.html`
into a receipt. The certified `rolling_hash` is recomputed with `replay`
over the export's own events, and the receipt carries
`extra.ingest = "replayed-export"` and
`extra.export_rolling_hash_matches`. When the export's declared hash does
not match its own events, the receipt is still written, a warning goes to
stderr, and the command exits 2. Otherwise 0; a read or parse error exits
1. Flags: `export` (positional), `--ledger` (default `writing.log.jsonl`),
`--namespace` (default `authorship`), `--out`, `--no-anchor`,
`--no-witness`. The anchor is on unless `--no-anchor`.

The MCP server (`authorship_mcp`) has tools `authorship_open`,
`authorship_event`, `authorship_close` and `authorship_ingest_export`.
Open sessions live only in the process; a restart loses an open session
(the ledger keeps the checkpoints written so far). Closing twice is
refused. Flags: `--ledger` (default `writing.log.jsonl`), `--receipts-dir`
(default `receipts`), `--namespace` (default `authorship`).

What it does NOT prove (from `authorship.SCOPE`):

- That a human produced the events: software can emit key events. This is
  process evidence, not a humanity test.
- That pasted text was written by the author, or was not generated by a
  model.
- Anything about text edited outside the recording session.

## ballot

Module: `ballot.py`. Receipt kind `ballot`.

What it does. Seals a finished training-sim grade. The ballot object is
stored verbatim as the check, with `ballot_digest` (sha256 of its
canonical JSON), trainee, scenario, grader and timestamp. `--issuer` and
`--cohort` are sealed inside the body digest under `extra`; blank values
are dropped. With `--roster` it mints one receipt per CSV row into one
ledger and writes `<trainee-slug>.receipt.json` and
`<trainee-slug>.exhibit.txt` into `--out-dir`. The roster (a CSV, read
as UTF-8) must have the
columns `trainee` and `ballot_path` (optional `scenario`, `grader`,
`timestamp`). A bad row (empty trainee, missing or unreadable ballot file,
no scenario, two trainees with the same slug) refuses the whole roster
before anything is minted.

When the witness pin is on, each ballot also appends one row to a pin
counter at `~/.arcaeon/ballot_pin_ledger.jsonl` (override with the
environment variable `ARCAEON_BALLOT_PIN_LEDGER`). A failed write says so
on stderr and does not stop the receipt.

Usage (`arcaeon receipt ballot`):

```text
arcaeon receipt ballot <ballot.json> --trainee NAME --scenario NAME
    [--grader G] [--timestamp TS] [--issuer ACADEMY] [--cohort CLASS]
    [--ledger L] [--namespace NS] [--out receipt.json] [--exhibit exhibit.txt]
    [--no-anchor] [--no-witness]
arcaeon receipt ballot --roster roster.csv [--scenario NAME] [--grader G]
    [--issuer ACADEMY] [--cohort CLASS] [--ledger L] [--namespace NS]
    [--out-dir DIR] [--no-anchor] [--no-witness]
```

Defaults: `--ledger receipts.log.jsonl`, `--namespace ballot`,
`--out-dir .`; `--out` defaults to `<ballot stem>.receipt.json`. The
library function `ballot_receipt` defaults the anchor off; the CLI passes
the anchor on unless `--no-anchor`. A single ballot needs the path,
`--trainee` and `--scenario`; `--roster` refuses a path or `--trainee`.

Words. There is no flagged-check concept: `ballot` exits 0 or 1 only. The
exhibit line prints the score and verdict the grader produced
(`overall.score`/`overall.verdict`, else `score`/`verdict`, else
`seq_pct`/`seq_verdict_label`), as data.

What it does NOT prove (from `ballot.SCOPE`):

- That the score is correct.
- That the sim was not attempted before.

## cite

Module: `cite.py`, `cite_batch.py`, `cite_mcp.py`. Receipt kind
`citation-existence`.

What it does. Sends the brief's text to CourtListener's citation-lookup
API (v4) and records, per citation, the status that came back:
`found` (200), `not_found` (404), `invalid_reporter` (400), `ambiguous`
(300), `not_checked_rate_limit` (429). Any citation-shaped text the service
did not return is added as `not_recognized_by_service`. The flagged
statuses are `not_found`, `invalid_reporter` and
`not_recognized_by_service` (`cite.FLAGGED`); `ambiguous` is marked `??` in
the exhibit and is not flagged. The live API needs `COURTLISTENER_TOKEN`
in the environment; `--fixture` replays a saved API response instead and
the receipt's `extra.transport` names it.

Usage (`arcaeon receipt cite`):

```text
arcaeon receipt cite <brief.txt> [--ledger L] [--namespace NS] [--out receipt.json]
    [--exhibit exhibit.txt] [--fixture saved_api_response.json]
    [--no-anchor] [--no-witness]
```

Defaults: `--ledger receipts.log.jsonl`, `--namespace citation-receipt`;
`--out` defaults to `<brief stem>.receipt.json`; the anchor is on unless
`--no-anchor`. The CLI sends one request, so a text over 64,000 characters
is refused (exit 1). The MCP tool `cite_check` goes through
`cite_batch.citation_receipt_batched`, which splits on paragraph
boundaries, re-bases spans onto the full text, and resubmits only the
paragraphs holding a rate-limited citation, at most 3 rounds
(`MAX_RETRY_ROUNDS`); anything still rate-limited stays
`not_checked_rate_limit`.

Exit: 3 from the module (1 through `arcaeon receipt`) when any check is
flagged; 0 otherwise.

`cite_mcp` flags: `--ledger` (default `receipts.log.jsonl`),
`--receipts-dir` (default `receipts`), `--namespace` (default
`citation-receipt`), `--fixture`, `--no-anchor`, `--no-witness`. Its
docstring and tool description list `ambiguous` among the flagged
statuses; the `flagged` list it returns comes from the checks' own
`flagged` field, which does not include `ambiguous`.

What it does NOT prove (from `cite.SCOPE`):

- That any cited authority supports the proposition it is cited for.
- That any cited authority is good law, current, unreversed, or quoted
  accurately.
- That the brief contains no other citations. Statutes, regulations,
  law-journal, id. and supra citations are never looked up.
- That a `found` citation was cited correctly, or that a `not_found`
  citation is fabricated: CourtListener's coverage is not complete.

## call_proxy

Module: `call_proxy.py` (receipts built by `call.py`). Receipt kind
`receipted-call`.

What it does. A reverse proxy in front of a seller's service. Every
request it forwards, and every response, gets one Receipted-Call receipt:
digests of the request body, the response body and any payment header,
the response status and elapsed time. It reads the upstream response to
completion, builds the receipt, then sends the client the status line,
non-hop-by-hop headers and body unmodified, plus two headers:
`X-Arcaeon-Receipt` (the receipt's body digest) and `X-Arcaeon-Receipt-URL`
(`/_arcaeon/receipt/<digest>`). `GET /_arcaeon/receipt/<digest>` serves the
receipt from an in-memory store of the last 1000, backed by
`--receipts-dir` when given. `GET /_arcaeon/health` reports the ledger.
If the upstream cannot be reached, the client gets a 502 and the call is
still receipted with `upstream_error` on the check. The anchor is always
off.

With `--tape PATH` it also keeps the tool side's call tape (one row per MCP
`tools/call`) for `arcaeon reconcile` against the agent side's tape. With
`--mandate PATH` it checks each `tools/call` against a mandate, record-only
unless `--mandate-enforce`; see [MANDATE_GATE.md](MANDATE_GATE.md).

Usage:

```text
python -m arcaeon.record.receipt.call_proxy --upstream URL
    [--listen HOST:PORT] [--seller NAME] [--ledger PATH] [--namespace NS]
    [--no-witness] [--receipts-dir DIR] [--raw-payloads] [--upstream-timeout S]
    [--tape PATH] [--tape-namespace NS]
    [--mandate PATH] [--mandate-enforce] [--mandate-log PATH]
```

Defaults: `--listen 127.0.0.1:8402`, `--ledger calls.log.jsonl`,
`--namespace receipted-call`, `--upstream-timeout 30.0`. `--upstream` is
required. `--raw-payloads` stores request and response bodies verbatim in
receipts and prints a warning to stderr at start. `--mandate-enforce`
without `--mandate` is a usage error. Exit: 3 when `--mandate-enforce` is
set and the mandate cannot be read (refuses to start), 1 on a bad
argument value, 0 when stopped.

Words. The proxy prints no verdict. On the tape, a call closes with its
answer, or `unanswered`, or `invalid_id`; the verdict on the two tapes
comes from `arcaeon reconcile` (MATCHED / MISSING / ALTERED / COULD NOT
LOOK).

`call_mcp` issues the same receipt for one call already made (tool
`call_receipt`). Flags: `--ledger` (default `calls.log.jsonl`),
`--receipts-dir` (default `receipts`), `--namespace` (default
`receipted-call`), `--seller`, `--no-witness`.

What it does NOT prove (from `call.SCOPE`):

- That the response was correct, complete, or what the listing promised.
  This is delivery evidence, not quality evidence.
- That the payment settled on any chain or was for the listed price: the
  payment header is digested, not verified.
- The content of the request or response: only digests are recorded unless
  raw payloads were turned on, and the receipt says which
  (`subject.raw_payloads`).

Not in the scope block but true of the proxy: only traffic that passes
through it is receipted. A call that reaches the seller another way leaves
no receipt.

`call.py` also has `phone_call_receipt` (kind `receipted-phone-call`):
participant ids, start and end, and a transcript hash. It refuses a
participant id that looks like a phone number. It does not prove the truth
of anything said, who the participants are, or that consent was given. It
has no CLI.

## archive

Module: `archive.py` (built on `roster_report.py` and `verify_batch.py`).

What it does. Packs a cohort into one zip a coordinator can hand to
anyone: `MANIFEST.json` (each file's sha256, each receipt's verdict, the
scope block verbatim), `README.txt` (how to check it without tools),
`roster_report.csv`, and `cohort/`, a flat byte-for-byte copy of every
receipt, exhibit, the ledger files they name and the witness sidecars.
Whole ledger files are copied, not subsets, because a hash chain cannot be
subset. Receipts are never re-serialized; their sha256 is recomputed from
the written zip before the command returns. A receipt that does not verify
is packed with its verdict. The manifest counts verdicts and carries no
statistic about scores. The same cohort archived twice gives the same
bytes apart from `generated_at`.

Usage (`arcaeon receipt archive`):

```text
arcaeon receipt archive <cohort-dir|class-ledger.jsonl> --out class.zip [--ledger L] [--ots]
```

`--out` is required. Without `--ledger`, each receipt is checked against
the ledger named on its own face, if that file sits beside it. `--ots`
also runs `ots verify` on anchors. Verification pages in runs of 20 (the
`verify --batch` cap) rather than refusing a larger class.

Words: VERIFIED, BROKEN, COULD NOT LOOK per receipt. The archive is written
at every verdict. Module exit: 0 every receipt VERIFIED, 2 at least one
BROKEN, 4 none BROKEN but at least one COULD NOT LOOK, 1 an error. Through
`arcaeon receipt`: 0, 1, 3, 1.

`roster-report` is the same verification as a table (one row per trainee,
CSV or `--json`), with the same words and exit codes; flags `--out`,
`--json`, `--ledger`, `--ots`.

What it does NOT prove: anything the receipts inside do not. A VERIFIED
row means the receipt's digests and ledger claim hold; the scope block of
each receipt still applies, and for ballots that includes "the score is
correct" in `does_not_prove`.
