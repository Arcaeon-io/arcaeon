# Verb reference

Every verb, in the order `arcaeon --help` lists them. For each one: the
question it answers, its usage line, the exit codes it can return, and one
example with real output (long output is cut with `...`).

The usage blocks are copied from `arcaeon <verb> --help` by
`tools/sync_verbs_usage.py`, and `tests/test_docs.py` fails if one goes stale.
Since 0.9.1 every usage line, subcommand help included, reads
`arcaeon <verb>`; what you see in a block is what you type.

The exit codes are one table for every verb (see the README): 0 good, 1 a bad
finding, 2 bad usage, 3 COULD NOT LOOK. `--legacy-exit` returns the old tool's
own code for the 0.9.x releases; where that differs, the section says so.

Over many logs, the three words stay side by side. Any summary arcaeon prints
across many ledgers or files (`status`, a batch of receipts) counts VERIFIED,
BROKEN and COULD NOT LOOK separately and never folds them into one rate: a
file nobody could read is not a pass and not a break, and a percentage would
make it look like one or the other.

Contents: Record (`log`, `verify`, `receipt`, `once`, `proxy`, `pin`, `deal`,
`mandate`), Prove (`reconcile`, `audit`, `vet`, `badge`, `seal`, `baseline`,
`compact`, `second-read`, `evidence-pack`, `export`), Save (`distill`, `dedup`,
`meter`), Hosted (`stamp`, `credits`, `buy`), Serve (`mcp`, `serve`, `connect`,
`schema`, `open`), This install (`status`, `selftest`, `version`, `doctor`,
`demo`).

A section whose whole body is a TODO marker naming a batch item is a verb
registered before its code landed: until that code is in, the verb answers
`arcaeon <verb>: not built in this checkout` and exit 2, and the release
check fails until the code and the section are both written.

---

## `log`

Answers: how do I add a row to a ledger? Appends one JSON object as a new
chained row and prints the row's chain value.

**Usage**

```text
usage: arcaeon log <ledger.jsonl> '<json object>' | - | --field KEY=VALUE ...
```

The row comes one of three ways: a JSON object as one argument, `-` to read
it from stdin, or `--field KEY=VALUE` (repeatable, value kept as a string;
`--field KEY:=JSON` parses the value, so `n:=5` is the number 5). `--field`
needs no JSON quoting, so the same line works in PowerShell, cmd and sh.
Fields given with a JSON or stdin row are added over it.

**Exit codes:** 0 the row was written. 1 the row was not JSON, or not a JSON
object. 2 wrong number of arguments, or a `--field` that is not `KEY=VALUE`.
3 the ledger's last line cannot be chained from (nothing was written).

```console
$ arcaeon log agent.jsonl '{"tool": "search", "query": "weather"}'
bf1e1b19380ce8062d9332cbf3af16fb
$ arcaeon log agent.jsonl --field tool=search --field query=weather
7546586e4171ae219677971ceb34c193
```

## `verify`

Answers: has this ledger been changed since it was written? Recomputes the
chain over every row and names the first break.

**Usage**

```text
usage: arcaeon verify <ledger.jsonl> [--strict] [--witness PINS [--ns NS]]
```

**Exit codes:** 0 VERIFIED, every row checked. 1 BROKEN. 3 COULD NOT LOOK:
the file could not be read (missing, a directory, no permission), or no break
was found but unchained rows before the chain began were skipped, so not every
row was checked (`--strict` turns those into a break). 2 wrong arguments.
Through 0.9.0 an unreadable file was BROKEN, exit 1; `--legacy-exit` keeps that
for the 0.9.x releases. A COULD NOT LOOK report carries `looked_for`, `where`
and `reason_word` (`missing`, `unreadable`, `empty` or `bounded`), and says the
same in one line on stderr.

`--witness PINS` compares against a local pin file (the one `arcaeon pin
--witness` writes): the report gains `since_pin`, the rows added since the
ledger's last pin there, and stderr says it in words. A ledger holding FEWER
rows than its pin had rows cut off the end, which the chain alone cannot see:
that is BROKEN, exit 1. `--ns` picks the namespace when the pin file holds
more than one.

```console
$ arcaeon verify agent.jsonl
{
 "verdict": "VERIFIED",
 "ok": true,
 "rows": 2,
 "chained": 2,
 "prechain": 0,
 "first_break": null,
 "breaks": 0,
 "verified_scope": "full",
 "declared_breaks": 0,
 "declared": []
}
```

## `receipt`

Answers: can I hand someone a single file that proves a check ran, and let
them verify it without me? Issues receipts (`cite`, `ballot`,
`roster-report`, `archive`, `exhibit`) and checks them (`verify`).

**Usage**

```text
usage: arcaeon receipt [-h] [--version]
                       {cite,ballot,verify,roster-report,archive,exhibit} ...
```

**Exit codes:** 0 good. 1 a receipt that does not verify, or a flagged check.
3 COULD NOT LOOK at one or more receipts. 2 bad usage. Under `--legacy-exit`:
2 for a failed verify, 3 for a flagged check, 4 for COULD NOT LOOK.

Note: `receipt cite` looks each citation up online.

```console
$ echo '{}' > r.json
$ arcaeon receipt verify r.json
{
 "ok": false,
 "body_digest_ok": false,
...
 "notes": [
  "body digest mismatch: a body field was altered after issue"
...
```

(exit 1)

## `once`

Answers: did this side effect (a refund, an email) run once, never, or is it
stuck half done? Reads a key's executed-once receipt from a ledger, frees one
crashed key after proving its holder is dead, or rebuilds the index.
Subcommands: `receipt LEDGER KEY`, `reclaim LEDGER KEY`,
`rebuild-index LEDGER`.

**Usage**

```text
usage: arcaeon once receipt|reclaim|rebuild-index <ledger> [key]
```

`arcaeon once --help` prints the module's description, which starts:
`arcaeon once -- inspect a key's receipt, reclaim one crashed key, or
rebuild the concurrency index.`

**Exit codes:** 0 the command ran (a receipt may still say `"state":
"never"`; that is information, not a failure). 1 bad usage, a ledger that did
not verify when `receipt` checked it, or a `reclaim` that refused.

```console
$ arcaeon once receipt agent.jsonl refund:pi_123
{
 "key": "refund:pi_123",
 "state": "never",
...
 "ledger_ok": true,
...
}
```

## `proxy`

Answers: what did my agent actually call, recorded by something other than
the agent? Wraps an MCP server (stdio, or HTTP with `--http-forward`) and
writes one row per message to a seam ledger. Payloads are stored as digests
unless you pass `--raw`.

**Usage**

```text
usage: arcaeon proxy [-h] --ledger LEDGER [--server SERVER]
                     [--session SESSION] [--raw] [--max-frame MAX_FRAME]
                     [--tape TAPE] [--side {agent,tool}]
                     [--tape-namespace TAPE_NAMESPACE] [--pin-witness URL]
                     [--tape-pair TAPE_PAIR] [--http-forward URL]
                     [--listen HOST:PORT] [--upstream-timeout SECONDS]
                     [--mandate PATH] [--mandate-enforce] [--policy FILE]
                     [--access-names] [--version]
                     ...
```

Everything after `--` is the server command to wrap.

**Exit codes:** the wrapped server's own exit code. 127 if the server could
not start. 2 bad usage.

```console
$ arcaeon proxy --ledger seam.jsonl -- python my_server.py
```

It prints nothing of its own: stdout is the MCP protocol channel. Afterwards,
`arcaeon verify seam.jsonl` checks the record.

## `pin`

Answers: how do I stop someone quietly cutting the end off my ledger? Hands
the ledger's current head (row count and chain) to a witness: a local pin
file with `--witness FILE`, or the hosted witness with `--remote` (needs
`ARCAEON_KEY`).

`--ns` is required with `--witness`. With `--remote` it may be left out: the
namespace is then `<your key's prefix>-ledger-<id>`, where the id comes from
the ledger's first row (never its path), so each ledger gets its own. It
works the way `seal` does: it tries `arcaeon-ledger-<id>`, and if the witness
refuses that and names your key's prefix (the refusal costs no credit), it
retries once under your prefix. The namespace used is printed with the pin.

**Usage**

```text
usage: arcaeon pin [-h] [--ns NS] (--witness WITNESS | --remote) [--renew]
                   ledger
```

**Exit codes:** 0 pinned. 1 not pinned (the ledger does not verify, the pin
file refused it, or the hosted witness said no). 2 bad usage.

```console
$ arcaeon pin agent.jsonl --ns demo --witness pins.jsonl
{
 "ok": true,
 "pin": {
  "namespace": "demo",
  "rows": 2,
  "chain": "1cd546deef735024c099cf23d3e62772",
  "as_of": "2026-09-24T12:40:39Z",
  "received_at": null,
  "prev": "witness-genesis",
  "self": "6efe39305dfcaaecc7816c3c62e73d24"
 }
}
```

A pin file you keep yourself shows the mechanism. It protects you only when
it sits somewhere the log's writer cannot reach.

## `deal`

Answers: did the buyer's agent and the seller record the same purchase?
Each side writes the steps (`mandate`, `commit`, `pay`, `ship`, `deliver`,
`cancel`) on its own ledger; `dispute` lines the two up and `pack` writes the
result out for a person. The full walk-through is [DEAL.md](DEAL.md).

**Usage**

```text
usage: arcaeon deal <step> ...
```

**Exit codes:** `dispute` and `pack`: 0 MATCHED, 1 MISSING or ALTERED, 3 COULD
NOT LOOK, 2 bad usage. The step verbs: 0 written, 2 bad usage. New in 0.9.0,
so `--legacy-exit` changes nothing here.

```console
$ arcaeon deal dispute d-demo1 --buyer buyer.jsonl --seller seller.jsonl
MATCHED 2 of 2 compared steps
...
```

(The commands that build those two ledgers are in DEAL.md, and the test suite
runs them.)

## `mandate`

Answers: what does this mandate file actually allow, and is this one call
inside it? Reads the mandate file the proxy's gate reads (the same code,
imported) and says what is in it: `lint` names unknown keys and bad types,
`explain` prints the mandate in plain sentences, `check` answers one call
(`--field name=<tool>` and each argument) with the gate's word. Record-only:
nothing here forwards, blocks or writes a ledger row.

**Usage**

```text
usage: arcaeon mandate [-h] {lint,explain,check} ...
```

**Exit codes:** 0 inside (check) or valid (lint, explain). 1 outside (check).
2 an invalid mandate or bad usage. 3 COULD NOT LOOK (the file is not there
or cannot be read, or a field the check needs is not readable).

```console
$ arcaeon mandate lint mandate.json
mandate.json: valid (tool shape, 0 problem(s), 0 warning(s))
$ arcaeon mandate check mandate.json --field name=place_order --field total=19.00
inside: spend: seller, currency, cap and window are inside the mandate
$ arcaeon mandate check mandate.json --field name=delete_account
outside: tool 'delete_account' matches no allowed_acts pattern
```

## `reconcile`

Answers: do two independent records of the same calls agree? Takes the
agent side's tape and the tool side's tape (the format `proxy --tape` writes)
and returns MATCHED, MISSING, ALTERED or COULD NOT LOOK, with the call where
they part.

**Usage**

```text
usage: arcaeon reconcile <tape_a> <tape_b> [--pin PIN] [--legacy-exit]
```

**Exit codes:** 0 MATCHED. 1 MISSING or ALTERED. 3 COULD NOT LOOK (a tape
missing or unreadable, both empty, a pin unreadable). 2 bad usage. Under
`--legacy-exit`, COULD NOT LOOK is 2.

```console
$ arcaeon reconcile agent.tape.jsonl tool.tape.jsonl
{
 "verdict": "COULD_NOT_LOOK",
 "summary": "COULD NOT LOOK: tape_a not found: agent.tape.jsonl",
...
 "exit_code": 3
}
```

Every result carries a `limits` list saying what MATCHED does not prove.

## `audit`

Answers: can I check a log, pin its head, and hand the whole thing over as
one bundle? Subcommands `verify`, `pin`, `export`.

**Usage**

```text
usage: arcaeon audit [-h] [--version] {verify,pin,export} ...
```

**Exit codes:** 0 good. 1 a bad finding. 3 the check could not complete (for
example a log it could only partly check, or an unreadable witness file).
2 bad usage. Under `--legacy-exit`, could-not-complete is 2.

**The bundle's verdict:** `export` writes integrity.json with `verdict` first
(VERIFIED, BROKEN or COULD NOT LOOK) and `finding` second (the detailed
string: PASS, VERIFIED_MODULO_TRUNCATION, EMPTY_LOG, FAIL, TRUNCATION_DETECTED,
REWRITE_DETECTED, WITNESS_CHECK_FAILED, UNVERIFIED_SCOPE, ...). The headline
word follows the exit code; the finding carries the truncation case
(VERIFIED_MODULO_TRUNCATION), which the word alone reads as VERIFIED. An empty
log (EMPTY_LOG) is COULD NOT LOOK, exit 3, as `arcaeon verify` says of an
empty file. Before 0.9.0 the detailed string was in `verdict`.

```console
$ arcaeon audit verify agent.jsonl
VERIFIED ... 2 records, integrity intact (no tampering detected). Note: chain verification cannot detect TRUNCATION; use `pin` + `export --witness` to close that gap.
```

## `vet`

Answers: does this MCP server's source contain the patterns that usually go
wrong (unsafe exec, unsafe deserialization, SSRF, path traversal, no auth,
secrets in code, and more)? Reads the source; runs none of it. `arcaeon vet
PATH` grades a file or folder. Subcommands: `scan`, `grade`, `grade-target`,
`badge`, `verify` (does a grade reproduce), `serve`, `audit-verify`, `probe`
(the one that runs the server, opt-in, needs `arcaeon[mcp]`).

**Usage**

```text
usage: arcaeon vet [-h]
                   {scan,grade,grade-target,badge,verify,serve,audit-verify,probe} ...
```

**Exit codes:** 0 no high-severity findings in the checked classes. 1 a
high-severity finding, a grade that did not reproduce, or a broken
audit chain. 3 NO GRADEABLE FILES (nothing to grade, no file that parses, or
only TypeScript without `arcaeon[ts]`: the hint says `pip install
'arcaeon[ts]'`), or `probe` could not connect. 2 bad usage or path trouble. Under `--legacy-exit`: `verify` and `audit-verify` return 2
for a bad result, `probe` returns 2 for could not connect, `badge` returns 4
for a refused `--sealed`.

```console
$ arcaeon vet server.py
{
  "tool": "mcp_vet",
  "tool_version": "0.0.17",
  "target": "server.py",
...
  "findings": [],
...
  "verdict": "no findings in checked classes",
...
}
```

The report lists its own blind spots. It is what these checks found in these
bytes, not a review by a person.

## `badge`

Answers: can I show what the checks found, in a README? Prints a Markdown
badge and the JSON report behind it. Free, offline. `--receipt` signs the
report when a signing key and `arcaeon[sign]` are present, and prints
UNSIGNED and why when they are not; `--sealed` is the paid path (see `seal`).

**Usage**

```text
usage: arcaeon badge [-h] [--receipt] [--sealed] [--ns NS] path
```

**Exit codes:** as `vet`. A refused `--sealed` is 3 (4 under
`--legacy-exit`); the free badge still prints.

```console
$ arcaeon badge server.py
![mcp-vet scan report](data:image/svg+xml;base64,...)

{
  "tool": "mcp-vet",
  "tool_version": "0.0.17",
  "target": "server.py",
  "verdict": "no findings in checked classes",
...
}
```

## `seal`

Answers: can the badge carry a mark from someone other than me? Grades the
server, then seals the report with the hosted witness. Paid: needs
`ARCAEON_KEY` and uses one credit. That key is the only thing it needs.
Without it nothing is sent.

The witness's pin is the seal. The report is appended to a local ledger and
the ledger's head (rows and chain) is pinned with the witness; the pin
endpoint takes only `{namespace, rows, chain}` and checks no signature from
your machine (the evidence is in MIGRATION.md, "seal"). With the
`arcaeon[sign]` extra and a signing key in `MCP_VET_RECEIPT_KEY`, the report
is also signed and the seal records it as `"signed": "SIGNED"`; without them
it is sealed all the same and records `"signed": "UNSIGNED"`.

A key pins only under its own namespace prefix, and you do not need to know
yours. Without `--ns`, `seal` tries `mcp-vet-sealed-scans`; if the witness
refuses that and names your key's prefix, it retries once under
`<prefix>-sealed-scans` and remembers the prefix for the rest of the process.
The refusal costs no credit, so it is still one credit per seal. The JSON's
`sealed_scan.namespace` says where the pin landed. `--ns` picks the namespace
yourself and is never retried; if the witness refuses it, the message names
the namespace it tried and the exact `--ns` your key needs.

**Usage**

```text
usage: arcaeon seal <path-to-mcp-server> [--ns NAMESPACE]
```

**Exit codes:** 0 sealed. 3 not sealed (no key, no balance, a namespace your
key may not pin, or the witness could not be reached); the free badge still
prints. 1 a high-severity finding. 2 bad usage.

```console
$ ARCAEON_KEY=... arcaeon seal server.py
![mcp-vet scan report](data:image/svg+xml;base64,...)
...
  "sealed_scan": {
    "sealed": true,
    "namespace": "wk-abc-sealed-scans",
...
    "signed": "UNSIGNED"
  }
}
```

With no `ARCAEON_KEY` it prints "sealed scan is a paid Arcaeon tool and no
ARCAEON_KEY is set, so nothing was sent", with where to get a key, and exits 3.

## `baseline`

Answers: did a change (a new model, a new prompt) move behaviour on a fixed
set of probes? `register` scores the probe set now and records the result;
`compare` runs the same probes later and reports the difference.

**Usage**

```text
usage: arcaeon baseline [-h] [--version] {register,compare,selftest} ...
```

**Exit codes:** 0 the command ran. 1 `compare` refused: the probe set is not
the one that was registered. 2 bad usage.

```console
$ arcaeon baseline selftest
...
  PASS  compare: changed probe set -> valid=False
  PASS  compare: changed probe set -> names the reason

ALL CHECKS PASSED
```

`register` and `compare` run your own model command against the probe set;
the self-check shows the mechanism without one.

## `compact`

Answers: when an agent compacted its context, what exactly did it drop? Checks
a compaction receipt row. Alone it checks the receipt is self-consistent; with
`--pre` and `--post` it recomputes the digests from the content.

**Usage**

```text
usage: arcaeon compact [-h] [--pre PRE] [--post POST] receipt
```

**Exit codes:** 0 VERIFIED. 1 BROKEN. 3 COULD NOT LOOK (a file could not be
read). 2 bad usage.

```console
$ arcaeon compact row.json --pre pre.json --post post.json
{
 "verdict": "VERIFIED",
 "ok": true,
 "self_consistent": true,
 "content": "match",
 "schema": "v2",
 "understatement_check": "full",
 "verified_scope": "full",
 "notes": []
}
```

The receipt proves what was dropped, never that dropping it was wise.

## `second-read`

Answers: did a second model, reading the same claims against the same
frozen sentence, come out where the first one did? `arcaeon second-read
<criterion|compare|submit|ask|run> ...`: `criterion` freezes one criterion
sentence into a readings ledger (every reading cites its sha256); `submit`
files your own reading of one claim (the door for any AI or person, the
same as `POST /v1/readings`); `ask` puts a claims file to one reader, one
reading per claim, as a dry run unless `--send`; `compare A B` lines up two
readings ledgers claim by claim and files each disagreement with both
readings; `run` puts one claims file to two readers and compares the two
ledgers, as a dry run unless `--send`. `--receipt OUT` on `compare` and
`run` issues a local receipt for the comparison. COMPARED means both
ledgers were read and lined up, never that the claims are true.

**Usage**

```text
usage: arcaeon second-read <subcommand> [args...]
```

**Exit codes:** exit 0 COMPARED, 1 MISSING or BROKEN, 2 bad usage, 3 COULD
NOT LOOK. A disagreement inside a COMPARED is filed, not failed: it does not
change the exit.

## `evidence-pack`

Answers: can I hand one folder to an auditor, a buyer or a regulator's
reviewer that holds the records for one agent and one time window, with
everything they need to check it themselves? `arcaeon evidence-pack --ledger
L --out DIR` writes that folder: the rows in the window, a manifest hashing
every file, the chain check, and a plain summary. It is evidence toward the
EU AI Act logging duties, never a claim of compliance. Optional parts:
`--witness` and `--namespace` check the ledger's pins against a witness
store; `--mandate` folds in the mandate gate's inside / outside /
could-not-look counts and the outside rows; `--readings` includes a
second-read comparison receipt (receipt verify runs on it at build and on
every pack verify); `--deal` folds in one deal's dispute; `--format aat`
also writes agent-audit-trail JSONL; `--zip` also writes `OUT.zip`, and with
`--built-at` two builds of the same input are byte-identical.

`arcaeon evidence-pack verify PACK` (a folder or the `.zip`) rehashes every
file against the manifest and reruns the chain. `--witness` checks the
local pins; `--remote` reads each remote pin from the public witness (the
only part that uses the network, and only when asked; unread, a remote pin
is not verified).

**Usage**

```text
usage: arcaeon evidence-pack [-h] --ledger LEDGER --out OUT [--agent AGENT]
                             [--from SINCE] [--to UNTIL] [--witness WITNESS]
                             [--namespace NAMESPACE] [--system-id SYSTEM_ID]
                             [--provider PROVIDER] [--format {aat}]
                             [--deal DEAL] [--buyer BUYER] [--seller SELLER]
                             [--mandate MANDATE] [--readings READINGS]
                             [--readings-ledger READINGS_LEDGER] [--zip]
                             [--built-at BUILT_AT] [--json]
```

**Exit codes:** 0 VERIFIED. 1 BROKEN. 2 bad usage. 3 COULD NOT LOOK.

```console
$ arcaeon evidence-pack --ledger calls.jsonl --out pack --zip --built-at 2026-09-27T00:00:00Z
$ arcaeon evidence-pack verify pack.zip
```

## `export`

Answers: can another tool read my ledger in the record format it already
speaks? `arcaeon export LEDGER --format agent-audit-trail --out FILE.jsonl`
writes the ledger as draft-sharif-agent-audit-trail records, JSONL only. Each
record holds only the fields the row itself holds (a field the row lacks is
left out, never guessed), its `prev_hash` over the RFC 8785 JCS of the record
before it, and our original `chain` and `source_line` beside it, because a
chain computed at export proves the export, not the original. It is a subset
of the draft, not a conformance claim. Beside the export it writes
`FILE_gaps.json`: which chain is which, and one COULD NOT LOOK `bounded`
entry per field left out. `--out` must be a new file; an existing one is
refused.

**Usage**

```text
usage: arcaeon export [-h] --format {agent-audit-trail} --out OUT [--json]
                      ledger
```

**Exit codes:** the source ledger's own chain check, since the export copies
what is there either way and says what it copied: 0 VERIFIED, 1 BROKEN. 2 bad
usage (an existing `--out`, a non-JSONL name). 3 COULD NOT LOOK (the ledger
is missing or unreadable).

```console
$ arcaeon export calls.jsonl --format agent-audit-trail --out calls.aat.jsonl
```

## `distill`

Answers: how do I fit a big tool output into a token budget without losing
track of what was cut? Cuts deterministically and returns a receipt of the
drop. `arcaeon distill serve` runs it as an MCP server.

**Usage**

```text
usage: arcaeon distill [-h] [--budget BUDGET] [--query QUERY]
                       [--schema-hint {json,tabular,text}]
                       input
```

**Exit codes:** 0 done. 2 bad usage or an unreadable input file.

```console
$ arcaeon distill out.json --budget 60
{
 "content": [
  {
   "id": 0,
   "name": "row 0",
...
  {
   "__distilled_dropped_rows__": 36
  },
...
```

## `dedup`

Answers: which of these texts are near-copies of one another? Keeps the first
(or `--keep last`) of each group and reports what it removed.

**Usage**

```text
usage: arcaeon dedup [-h] [--max-hamming MAX_HAMMING]
                     [--min-overlap MIN_OVERLAP] [--keep {first,last}]
                     input
```

**Exit codes:** 0 done. 2 bad usage or an unreadable input file.

```console
$ printf 'the build passed\nthe build passed\nthe deploy failed\n' > notes.txt
$ arcaeon dedup notes.txt
{
 "kept": [
  "the build passed",
  "the deploy failed"
 ],
 "report": {
  "kept": 2,
  "removed": 1,
  "chars_saved": 16,
  "est_tokens_saved": 4,
  "removed_indices": [
   1
  ]
 }
}
```

## `meter`

Answers: how much has each API key used this month, and is it over its cap?
Subcommands: `keys` (add, revoke, list; secrets are stored hashed), `usage`,
`export`.

**Usage**

```text
usage: arcaeon meter [-h] [--version] {keys,usage,export} ...
```

**Exit codes:** 0 done. 1 an unknown key or a refused value (a bad month, a
bad cap). 2 bad usage.

```console
$ arcaeon meter keys --help
usage: arcaeon meter keys [-h] {add,revoke,list} ...
...
    add              mint a key; prints the secret ONCE
    revoke           revoke by key_id or secret
    list             list keys (ids only, never secrets)
```

## `stamp`

Answers: can someone else say this exact file existed by now? Sends the
file's sha256 and size, never its bytes, to the hosted witness. Works without
a key, inside a free daily allowance.

**Usage**

```text
usage: arcaeon stamp <file>
```

**Exit codes:** 0 stamped. 1 the witness answered and said no (the answer is
printed as data, never a crash). 2 bad usage. 3 COULD NOT LOOK: the request
never completed (`reason_word` `network`), or the file is missing
(`missing`) or unreadable (`unreadable`), the same answer `verify` gives a
file it cannot read; nothing was stamped. A COULD NOT LOOK answer carries
`looked_for`, `where` and `reason_word`.

The example points at a witness that is not there, so it shows the failure
shape without sending anything:

```console
$ ARCAEON_WITNESS_URL=http://127.0.0.1:9 arcaeon stamp notes.txt
{
 "ok": false,
 "status": 0,
 "endpoint": "http://127.0.0.1:9/api/stamp",
 "error": "witness unreachable: ...",
 "verdict": "COULD NOT LOOK",
 "looked_for": "a stamp from the hosted witness",
 "where": "http://127.0.0.1:9/api/stamp",
 "reason_word": "network",
 "reason": "witness unreachable: ..."
}
```

(exit 3)

## `credits`

Answers: how many credits are left on my key? Reads `ARCAEON_KEY`. Looking
never uses a credit. Prints one sentence, such as `500 credits on the key`; a
key on an older plan with a monthly cap also shows its count, such as `1000
credits left, 7 of 100 free pins used this month`. `--json` prints the
witness's raw answer.

**Usage**

```text
usage: arcaeon credits [--json]
```

**Exit codes:** 0 the balance printed. 1 the witness answered and said no.
2 no `ARCAEON_KEY` set. 3 COULD NOT LOOK: the request never completed
(`reason_word` `network`; `--json` carries `looked_for` and `where` too).

```console
$ arcaeon credits
refused before sending: no ARCAEON_KEY. The witness key was empty or whitespace, and an empty bearer token is a credential-shaped thing that is not a credential. Set ARCAEON_KEY=<your witness key> and call again.
```

(exit 2, with no key set)

## `buy`

Answers: where do I pay? Prints the checkout link for a plan, from the offers
file bundled with the package. Opens no browser, takes no card, makes no
request. With no plan name it lists every plan. Prices: arcaeon.io/pricing.

**Usage**

```text
usage: arcaeon buy [-h] [--offers OFFERS] [plan]
```

**Exit codes:** 0 printed. 2 no such plan, or the offers file could not be
read.

```console
$ arcaeon buy witnessed
https://buy.stripe.com/6oUaEYd987LP3xy21b0RG04
```

## `mcp`

Answers: how does an agent use all this? Starts the MCP server on stdio with
the ledger, vet and witness tools. Needs `arcaeon[mcp]`. `--tools` prints the
tool list and exits without starting a server.

**Usage**

```text
usage: arcaeon mcp [-h] [--log LOG] [--ns-dir NS_DIR] [--tools] [--http]
                   [--port PORT]
```

**Exit codes:** 0 the server closed cleanly, or `--tools` printed. 2 the MCP
SDK is not installed (`pip install "arcaeon[mcp]"`). With `--http` (KH8: the
same server over streamable HTTP on `http://127.0.0.1:<port>/mcp`, the serve
token required, loopback only; `--port 0` picks one and prints it) a missing
SDK is 3 COULD NOT LOOK naming the extra, and a port that cannot be bound is 3.

```console
$ arcaeon mcp --tools
{
  "free": [
    "arcaeon_status",
    "ledger_append",
    "ledger_declare_break",
...
```

Until 1.0.0, `arcaeon` with no verb and a stdin that is not a terminal also
starts this server, so `uvx arcaeon` in an older registry listing keeps
working.

## `serve`

Answers: how does a model or framework that speaks HTTP, not MCP, use
arcaeon? Starts the local HTTP/JSON API: one route per check, each answering
with the same JSON the verb's own output carries plus an integer `exit`. It
binds 127.0.0.1 only; any other `--host` is refused, because putting the
server on a network is a deploy decision, not a flag. The URL is printed on
start, and `~/.arcaeon/serve.json` (or `$ARCAEON_HOME/serve.json`) names the
pid and port for as long as the server runs.

**Usage**

```text
usage: arcaeon serve [-h] [--host HOST] [--port PORT] [--root DIR]
                     [--allow-paid] [--print-token]
```

A verdict never rides in the HTTP status: VERIFIED, BROKEN and COULD NOT
LOOK all come back as 200 with `exit` 0, 1 or 3 in the body. The status
codes are for the request itself: 400 bad usage (not JSON, a field the
route refuses, a Host header that is not this loopback address), 404 no
such route, 405 the wrong method, 413 a body over 10 MB, 401 no token or
the wrong one.

Every route but `/health` and `/openapi.json` needs the token the first run
writes to `~/.arcaeon/serve.token` (owner-only where the OS allows), sent as
`Authorization: Bearer <token>` or `X-Arcaeon-Token: <token>`.
`arcaeon serve --print-token` prints it and exits. The token never appears
in the request log, the journal or an error body.

`--root DIR` (default: the directory serve starts in) is the only place a
request may name a path. Every path field, inputs and output directories
alike, is resolved against it with symlinks followed; one that lands
outside (`../x`, an absolute path elsewhere, a symlink pointing out) is
refused with 400 `outside the served root`. A relative path is relative to
the root, not to the server's working directory.

The paid lane (`POST /v1/seal`, and `POST /v1/pin` with `"remote": true`)
spends only with two opt-ins: `ARCAEON_KEY` set, and the server started with
`--allow-paid`. Missing either, the answer is a refusal sentence as COULD
NOT LOOK (`exit` 3, `refused: true`) and nothing is sent, so an agent can
never spend by surprise. A local pin to a witness file under the root is free.

Every call that reaches a handler is one line in the activity journal, verb
`serve:<route>` (`serve:/v1/verify`), with its verdict word, its exit and the
sha256 of the path it named, so `arcaeon status` shows HTTP work beside CLI
work. `/health` and `/openapi.json` are not journaled, nor is a request
refused before a handler ran. `ARCAEON_JOURNAL=0` writes nothing, and a
journal that cannot be written never changes a response.

**Exit codes:** 0 the server stopped cleanly (Ctrl+C), or `--print-token`
printed the token. 2 bad usage, including `--host` anything but 127.0.0.1.
3 the server could not start (the port is taken, the token file cannot be
read or created).

```console
$ arcaeon serve --port 0
arcaeon serve: listening on http://127.0.0.1:54817 (loopback only; Ctrl+C stops)
$ curl -s http://127.0.0.1:54817/health
{
 "ok": true
}
```

## `connect`

Answers: what exactly does my AI client need in its config to reach
arcaeon, and what would change if I let arcaeon put it there? `arcaeon
connect <client>` prints the config file it would change, the exact JSON it
would merge into it (only the `arcaeon` entry, under the client's own key),
and ends `nothing written (add --write to apply)`. By default it writes
nothing and creates nothing. `arcaeon connect --list` prints every client
it knows with its transport and whether the path is confirmed.

**Usage**

```text
usage: arcaeon connect --list [--json]
       arcaeon connect <client> [--os windows|macos|linux] [--json]
       arcaeon connect <client> --write|--undo|--check [--path FILE] [--json]
```

Clients: `claude-desktop`, `claude-code`, `cursor`, `windsurf`, `vscode`,
`gemini-cli` (each starts `arcaeon mcp` over stdio), `chatgpt` (reaches
tools only at a public HTTPS address; the loopback server is not one, so
it needs a public URL, which is a deploy decision; it names the GPT Action
manifest, `docs/schemas/gpt_action_openapi.json` or `arcaeon schema --format
gpt-action`, and `--write` exits 2) and `generic-http` (the URL, where the
token lives, and the OpenAPI URL of `arcaeon serve`).

Each path was read from the client's public docs on the date the catalog
records. Where those docs did not state the path, the output says
`confirmed: NO`; check the file before letting anything write it. `--os`
previews another machine (`~` or `%APPDATA%` stand in for its home).
`ARCAEON_CONNECT_HOME` replaces the home directory, for trying it on a copy.

The entry starts the server as `uvx --from "arcaeon[mcp]" arcaeon mcp` when
`uv` is on PATH, else as this Python's absolute path with `-m arcaeon mcp`,
so a client started outside your shell (from a dock or a menu) still finds
Python.

`--write` applies it on this machine. First it copies the file byte for
byte to `<file>.arcaeon-bak-<UTC stamp>` (a file that was not there gets an
`.absent` marker instead), then it splices in only the `arcaeon` entry:
every other server, key and line ending stays exactly as it was. It prints
the keys it changed and the backup path. A file it cannot parse (JSON with
comments included) is COULD NOT LOOK `unreadable` and is never overwritten.
A path marked `confirmed: NO` is refused (COULD NOT LOOK
`path_unconfirmed`) unless `--path FILE` names the file.

`--undo` moves the newest backup back over the file and consumes it (for a
file `--write` created, it removes the file and any directory it made), so
`--write` then `--undo` leaves the home byte-identical. `--check` reads only
and answers `present`, `absent`, or `stale` (the entry is there but its
command no longer resolves).

**Exit codes:** 0 printed, written, undone, or `--check` found it present.
1 `--check` found it absent or stale. 2 bad usage (no client, an unknown
client or option, an action with `--os` for another machine). 3 COULD NOT
LOOK: the file is unreadable, the path is unconfirmed, there is no backup
to undo, or the file could not be written; nothing was changed.

```console
$ arcaeon connect cursor --os linux
arcaeon connect cursor  (Cursor, stdio-mcp, linux)
file: ~/.cursor/mcp.json  (on another machine)
confirmed: yes
source: https://cursor.com/docs/context/mcp (read 2026-09-27)
note: global file; a project's .cursor/mcp.json takes the same key
would merge (only the 'arcaeon' entry; every other key stays):
{
  "mcpServers": {
    "arcaeon": {
      "command": "uvx",
      "args": [
        "--from",
        "arcaeon[mcp]",
        "arcaeon",
        "mcp"
      ]
    }
  }
}
nothing written (add --write to apply)
```

## `schema`

Answers: what does the local HTTP API accept and return, in the shape my
model or framework reads? `--format` picks one of five, every one built
from the same route table `arcaeon serve` dispatches on:

- `openapi` (the default): the OpenAPI 3.1 document the server answers at
  `GET /openapi.json`: one operation per route with an `operationId`, each
  route's request and response schemas under `components.schemas`, and the
  bearer security scheme on every route but `/health` and `/openapi.json`.
- `claude`: Claude tool use, a list of `{name, description, input_schema}`.
- `openai`: OpenAI function calling, a list of `{type: "function", name,
  description, parameters}`.
- `gemini`: Gemini function declarations, the parameters cut to the schema
  subset Gemini reads.
- `gpt-action`: a GPT Action manifest, the OpenAPI document cut to the free
  check routes, its server url a placeholder (a public url is a deploy
  decision).

Every format but `openapi` is generated from the OpenAPI document (free
check routes only), never written by hand. `docs/openapi.json` and
`docs/schemas/*.json` are this output, each held to it by a drift test.

**Usage**

```text
usage: arcaeon schema [-h]
                      [--format {openapi,claude,openai,gemini,gpt-action}]
                      [--out FILE]
```

`--out FILE` writes the document to a file (UTF-8, LF line endings) instead
of printing it.

**Exit codes:** 0 printed or written. 2 bad usage (an unknown `--format`).
3 the `--out` file could not be written.

```console
$ arcaeon schema --format openapi | py -c "import json,sys; d=json.load(sys.stdin); print(d['openapi'], len(d['paths']))"
3.1.0 21
```

## `open`

Answers: how do I see what arcaeon has on this machine without typing
commands? `arcaeon open` opens the local dashboard in a browser: a running
`arcaeon serve` found through serve.json, else one it starts here on
127.0.0.1. The browser gets a sign-in link with a one-time code; the code
becomes an HttpOnly cookie and is no good a second time. `--no-browser`
prints the link instead of opening it.

**Usage**

```text
usage: arcaeon open [-h] [--no-browser] [--port PORT] [--root DIR]
```

A server it starts keeps serving until it is stopped (Ctrl+C).

**Exit codes:** 0 opened, or the link printed. 2 bad usage (a port out of
range, a `--root` that is not a directory). 3 COULD NOT LOOK: a running
server would not give a sign-in code, or no server could be started.

```console
$ arcaeon open --no-browser
```

## `status`

Answers: what did arcaeon do lately on this machine, and is anything still
unlooked-at? Reads the local activity journal (`~/.arcaeon/activity.jsonl`,
or `$ARCAEON_HOME`): the last run of each verb with its word and time, and
the targets whose newest look ended COULD NOT LOOK. The journal stores each
target as a sha256, never the path, so a target is shown by its first 12 hex
digits. The balance is checked only when `ARCAEON_KEY` is set; without a key
no request is made. `ARCAEON_JOURNAL=0` stops the journal being written.
The `mandate` line sums every mandate-gated session recorded in
`~/.arcaeon/mandate_sessions.jsonl`: sessions, inside, outside, COULD NOT
LOOK, blocked, cap exceeded and mandate file changes (`--json` carries them
under `mandate` as `sessions`, `inside`, `outside`, `could_not_look`,
`blocked`, `cap_exceeded`, `changes`). HTTP calls to `arcaeon serve` show
as `serve:<route>`.

**Usage**

```text
usage: arcaeon status [--json]
```

**Exit codes:** 0 the status printed. 2 an unknown flag.

```console
$ arcaeon status
arcaeon status  (journal: ~/.arcaeon/activity.jsonl)
last run per verb:
  verify     COULD NOT LOOK     2026-09-25T10:02:00Z
  log        OK                 2026-09-25T10:01:00Z
open COULD NOT LOOKs: 1
  verify     target 3f1c9a0b7d22  2026-09-25T10:02:00Z
mandate: 2 gated sessions: 14 inside, 1 outside, 0 COULD NOT LOOK, 1 blocked, 0 cap exceeded, 0 mandate file changes
balance: not checked, no key
```

## `selftest`

Answers: does this install do what it claims, on this machine? Runs the
bundled self-checks (all of them, or the ones you name). Each one plants the
failure it exists to catch and checks that it is caught.

**Usage**

```text
usage: arcaeon selftest [ledger adapter once compact continuity baseline distill]
```

**Exit codes:** 0 every self-check passed. 1 at least one failed. 2 an
unknown name.

```console
$ arcaeon selftest ledger
...
  PASS  edit row 3 in place -> ok=False first_break='line 3: chain mismatch' (must be 'line 3: chain mismatch')
...
ALL CHECKS PASSED
{
 "selftests": {
  "ledger": 0
 },
 "failed": []
}
```

## `version`

Answers: which version is installed, and where did each part come from?

**Usage**

```text
usage: arcaeon version [--short]
```

`arcaeon version` prints the report: the package version, one line naming
the optional extras installed (`mcp`, `ts`, `sign`) and whether `ARCAEON_KEY`
is set (`key: set` or `key: not set`; never the key itself, since a version
report gets pasted into bug reports), then each moved family's version.
`--short` prints the package version alone.

**Exit codes:** 0.

```console
$ arcaeon version --short
0.10.0
```

## `doctor`

Answers: is this install ready, and what would stop it working? `arcaeon
doctor` prints one line per thing it looked at: the Python version, which
extras are installed, whether ARCAEON_KEY is set (never its value), whether
a local `arcaeon serve` answers, whether each AI client's config carries an
`arcaeon` entry, and whether the activity journal can be written. It
changes nothing: it reads files, asks `GET /health` only of a server on
this machine, and opens and removes one temp file to prove the journal
directory is writable.

**Usage**

```text
usage: arcaeon doctor [--json]
```

**Exit codes:** 0 every check was read, whatever it found (a server that is
not running or a client with no entry is a reading, not a fault). 3 COULD
NOT LOOK: a check could not be looked at (a config file that does not
parse, a serve.json naming a host off this machine, a server that neither
answers nor refuses). Never green on 3.

```console
$ arcaeon doctor --json
```

## `demo`

Answers: what does arcaeon actually do, in thirty seconds, on my own
machine? `arcaeon demo` makes a temp folder, logs two rows to a ledger
there, checks it (VERIFIED), changes one word on line 1 the way a quiet
edit would, checks again (BROKEN, naming line 1), and removes the folder.
No network, nothing left behind.

**Usage**

```text
usage: arcaeon demo
```

**Exit codes:** 0 the demo showed what it says (VERIFIED, then BROKEN on
line 1). 1 either check came back any other way. 2 bad usage.

```console
$ arcaeon demo
```
