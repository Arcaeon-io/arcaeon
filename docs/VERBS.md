# Verb reference

Every verb, in the order `arcaeon --help` lists them. For each one: the
question it answers, its usage line, the exit codes it can return, and one
example with real output (long output is cut with `...`).

The usage blocks are copied from `arcaeon <verb> --help` by
`tools/sync_verbs_usage.py`, and `tests/test_docs.py` fails if one goes stale.
A few verbs still print their old tool's name in the usage line
(`arcaeon-receipt`, `mcp_vet`, `arcaeon-audit`, and so on). That is the moved
code's own help text. Type `arcaeon <verb>`; the arguments are the same.

The exit codes are one table for every verb (see the README): 0 good, 1 a bad
finding, 2 bad usage, 3 COULD NOT LOOK. `--legacy-exit` returns the old tool's
own code for the 0.9.x releases; where that differs, the section says so.

Contents: Record (`log`, `verify`, `receipt`, `once`, `proxy`, `pin`, `deal`),
Prove (`reconcile`, `audit`, `vet`, `badge`, `seal`, `baseline`, `compact`),
Save (`distill`, `dedup`, `meter`), Hosted (`stamp`, `credits`, `buy`),
Serve (`mcp`), This install (`selftest`, `version`).

---

## `log`

Answers: how do I add a row to a ledger? Appends one JSON object as a new
chained row and prints the row's chain value.

**Usage**

```text
usage: arcaeon log <ledger.jsonl> '<json object>'
```

**Exit codes:** 0 the row was written. 1 the row was not JSON, or not a JSON
object. 2 wrong number of arguments.

```console
$ arcaeon log agent.jsonl '{"tool": "search", "query": "weather"}'
bf1e1b19380ce8062d9332cbf3af16fb
```

## `verify`

Answers: has this ledger been changed since it was written? Recomputes the
chain over every row and names the first break.

**Usage**

```text
usage: arcaeon verify <ledger.jsonl> [--strict]
```

**Exit codes:** 0 VERIFIED, every row checked. 1 BROKEN. 3 COULD NOT LOOK:
the file could not be read (missing, a directory, no permission), or no break
was found but unchained rows before the chain began were skipped, so not every
row was checked (`--strict` turns those into a break). 2 wrong arguments.
Through 0.9.0 an unreadable file was BROKEN, exit 1; `--legacy-exit` keeps that
for the 0.9.x releases.

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
                     [--version]
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

**Usage**

```text
usage: arcaeon pin [-h] --ns NS (--witness WITNESS | --remote) [--renew]
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
usage: arcaeon-meter keys [-h] {add,revoke,list} ...
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

**Exit codes:** 0 stamped. 1 the witness said no or could not be reached (the
answer is printed as data, never a crash). 2 bad usage or an unreadable file.

The example points at a witness that is not there, so it shows the failure
shape without sending anything:

```console
$ ARCAEON_WITNESS_URL=http://127.0.0.1:9 arcaeon stamp notes.txt
{
 "ok": false,
 "status": 0,
 "endpoint": "http://127.0.0.1:9/api/stamp",
 "error": "witness unreachable: ..."
}
```

## `credits`

Answers: how many credits are left on my key? Reads `ARCAEON_KEY`. Looking
never uses a credit.

**Usage**

```text
usage: arcaeon credits
```

**Exit codes:** 0 the balance printed. 1 the witness said no or could not be
reached. 2 no `ARCAEON_KEY` set.

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
usage: arcaeon mcp [-h] [--log LOG] [--ns-dir NS_DIR] [--tools]
```

**Exit codes:** 0 the server closed cleanly, or `--tools` printed. 2 the MCP
SDK is not installed (`pip install "arcaeon[mcp]"`).

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

`arcaeon version` takes no `--help`; it prints the report. `--short` prints
the package version alone.

**Exit codes:** 0.

```console
$ arcaeon version --short
0.9.1
```
