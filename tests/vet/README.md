# mcp_vet — an MCP-server checker (WORK IN PROGRESS)

**This is not a vetting authority and does not certify anything.** It is a
static scanner that looks for a small set of documented, high-signal failure
classes in MCP server source and reports what it finds, with the exact line.

Started 2026-08-29. It runs against our OWN servers first, and those findings
get published before it is ever pointed at a stranger's code.

Where the ideas came from, and who else they belong to: [`ORIGIN.md`](ORIGIN.md).

## What it checks (9 classes as of v0.0.17)
- **unsafe-exec** — a handler reaches `eval`/`exec`/`os.system`/`os.popen` or
  `subprocess(..., shell=True)`: arbitrary-code / shell-injection surface.
- **unsafe-deser**: `pickle` / `marshal` / `dill` / `cloudpickle` / `shelve` /
  `jsonpickle` loads, or `yaml.load()` without a safe Loader: arbitrary object
  construction from untrusted bytes. Always **high**.
- **ssrf** — a tool handler makes an outbound network call; **high** if the
  target traces to a tool parameter (input-controlled), **medium** otherwise.
- **path-traversal** — a tool handler passes tool input into `open()` /
  `read_text` / `write_*`: arbitrary file read or write from a tool argument.
- **zero-auth** — the server binds a *network* transport (`sse`/`http`) with no
  auth hint anywhere in the file. `stdio` (local pipe) is never flagged.
- **secret-in-code** (MCP01) — a credential sitting in the source at rest.
  **high** for a known vendor key shape (AWS `AKIA`/`ASIA`, Stripe
  `sk_live_`/`rk_live_`/`whsec_`, OpenAI `sk-`/`sk-proj-`, GitHub
  `ghp_`/`github_pat_`) — a prefix is a fingerprint, not a guess. **medium** for a
  high-entropy literal bound to a `*_KEY`/`*_TOKEN`/`*_SECRET`/`PASSWORD` name
  (variable, dict entry, or keyword argument), because entropy is a heuristic.
  Also catches a `.env`-shaped `NAME=value` line quoted in a docstring or comment:
  a key does not have to be *assigned* to leak. Findings are redacted — a scanner
  that prints the key it found is a leak with a report attached. `sk_test_` /
  `pk_live_` and anything loaded from `os.environ` are never flagged.
- **audit-record** (MCP08) — a served tool call that leaves no verifiable record
  behind. Four gates, one finding per server, severity set by the first gate not
  met, and the finding carries a `gates` dict so you see the whole ladder:

  | gate | question | unmet |
  |---|---|---|
  | 1 presence | does a tool call produce a record at all? | **high** |
  | 2 completeness | tool name + timestamp + args/digest? | **medium** |
  | 3 tamper-evidence | chain / hmac / ledger, or a plain rewritable log? | **medium** |
  | 4 reconstructability | is there a verify/replay path? | **low** |

  All four met is *silence* — the only class here that can come back clean as a
  compliment rather than as an absence of evidence. A `print()` is never a
  record. A `logging.info("done")` is not a record either: a log line that cannot
  say **which tool ran** cannot answer the question MCP08 asks. Evidence is
  reached from a decorator-registered handler **or** a hand-rolled `tools/call`
  dispatcher, through up to two hops of local helpers, because the audit write
  nearly always lives in an `_audit(...)` function. Design:
  `design/MCP08_audit_record.md`.
- **unreceipted-allow** — a gate function whose refusal is receipted (a
  hash/digest/audit/signature/chain field) and whose grant is bare. Not an
  OWASP MCP Top 10 number — a specific bug shape inside MCP08's territory,
  found by asking a sharper question than "does a call leave a record": when
  the gate says yes, does the yes leave the same kind of proof the no does?
  A gate built this way can prove every refusal and not one grant, which
  inverts the accountability a receipt is supposed to buy. Structural: reads
  dict-literal `return`s directly on a gate function, classifies each by a
  tight verdict field (`allowed`/`permitted`/`granted`/`approved`/`verdict`/
  `decision`, not the generic `ok`/`status`/`result`), and checks for a
  receipt-shaped key on each side. Design: `design/unreceipted_allow.md`.
- **except-returns-success**: an exception handler on a tool-reachable path
  returns a success-shaped value (`[]`, `{}`, `""`, `True`, a None-free dict or
  list literal, or a call building one) with no error marker in it. The failure
  is serialised into the tool result and the agent cannot tell it apart from a
  real answer: `return []` out of a caught exception reads as "there are none".
  Reachability is part of the rule, not a refinement, because the same return in
  a helper nobody serves is a contract rather than a lie. Three exclusions, each
  one a real false positive paid for by hand: a literal carrying its own error
  marker (`error`, `isError`, `errors`, `success: False`, `ok: False`), a
  documented polarity (a comment or a returned string that says which way this
  fails), and a handler that re-raises or hands back the caught exception. A
  `None`/`undefined` inside the literal is a modelled third state and is left
  alone. Runs on Python AND on TypeScript/JavaScript. The IDIOM was measured on
  six real MCP servers before this check existed: 20 real of 57 opened, 35.1%,
  by a scratch harness (`ORIGIN.md`). This check, re-run on the same six repos
  the day it was written, reproduced 1 of those 20, because its reachability
  walk could not follow a fetcher instance obtained from a call and did not
  recognise `@server.call_tool()` handlers. Both gaps were closed the same day:
  the walk now binds a local to the class a factory returns (`x = await
  get_fetcher(ctx); x.method()`) and follows it, and the low-level decorator is
  a handler root. Re-run on the same six trees it fires **27 times** and
  reproduces **9 of the 11 gate-2 real findings that are recoverable from the
  gate's record by file:line**; of the 53 candidate hits those reals were drawn
  from, 24 now fire where 0 did. All 27 were opened by hand: **24 real, 3
  false**, and then driven at runtime with a real failure injected: of the 24
  sites a harness could reach, **22 returned a success shape to the caller**
  and 2 raised (`ORIGIN.md`, runtime paragraph). The two named reals still missed are one body no tool handler reaches
  at all and one three call hops down, which the two-hop cap confesses. What the
  walk still cannot bind (a receiver held on an attribute, a method called
  straight off a factory's return value, a factory defined outside the scanned
  tree) is counted on the coverage line as "call(s) on unresolved instances"
  rather than guessed at, and is named in the blind-spot list. The 35.1% remains
  the idiom's number, not this check's. The six sibling idioms measured at the
  same time scored 1 real across 139 and are not shipped.

### Why this class is the differentiator
Snyk Agent Scan's ~21 issue codes (E001–E006, W001–W021) cover tool-description
poisoning, prompt injection, skill malware and secret handling. **None of them
tests whether a server keeps an audit record.**

That is a claim about somebody else's product, so here is how to check it rather
than take our word: read
[`snyk/agent-scan/docs/issue-codes.md`](https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md)
and search it. Fetched 2026-09-03: zero occurrences of "audit", "trail" or
"receipt"; the two hits for "record" are both about financial records as a class
of sensitive data (W017), not about a server keeping one. If that document
changes, this sentence is wrong and we would want to know before you do.

MCP08 is the one OWASP category
that is about a *control being present* rather than a bug being absent, which is
awkward for a vulnerability scanner and natural for a grade. We do not re-fight
poisoning and injection; we check the audit-trail control nobody tests, plus
line-level exec/auth/credential sinks, and we hand you a grade you can re-run.

## Install
```
pip install -e .              # scanner + CLI, no third-party dependencies at all
pip install -e ".[mcp]"       # adds the MCP Python SDK, needed only for `serve`
pip install -e ".[mcp,audit]" # adds arcaeon-ledger, the server's own call record
pip install -e ".[receipts]"  # adds cryptography, for Ed25519 grade receipts
```
Python 3.10+. The runtime dependency list is empty on purpose: a security
checker that drags in a dependency tree is a supply-chain surface of its own,
and the pitch here is a grade a skeptic can re-run cheaply. Verified 2026-08-30
by `pip install -e .` into a clean venv (contents afterwards: `mcp-vet`, `pip`)
followed by `mcp-vet --help` exiting 0.

## CLI
```
mcp-vet scan   <file>                # print findings, one line each
mcp-vet grade  <file>                # emit the re-testable grade as JSON
mcp-vet badge  <path> [--receipt]    # free Markdown badge + JSON report
mcp-vet verify <grade.json> <file>   # confirm a prior grade reproduces
mcp-vet serve                        # run as an MCP server over stdio
mcp-vet audit-verify [ledger]        # check the server's OWN call record
```
`scan` exits 1 if anything high-severity was found, `verify` exits 2 if a grade
does not reproduce. `audit-verify` exits 0 only on a full green, 2 on a broken
chain, and **3 when the verification was bounded or the record is empty** — no
rows is not a green.

## Badge

**`mcp-vet badge <path> [--receipt]`** is the free half of the sealed-scan plan
(`PRODUCT_BRIEF_test_honesty_audit_2026-09-04.md`, step 2 of 5): free to run,
free to publish, no network call, no LLM. Adoption-first by design
(`daniel_adoption_first_pricing_absorb_cost_2026-09-01` -- free to get, hard to
pass) -- issuing the badge costs nothing because it costs mcp-vet nothing to
run; the paid unit is the sealed, ledger-chained scan on a private repo,
elsewhere in this project, not this command.

```
$ mcp-vet badge mcp_vet/__init__.py
![mcp-vet scan report](data:image/svg+xml;base64,PHN2ZyB4bWxucz0i...)

{
  "tool": "mcp-vet",
  "tool_version": "0.0.17",
  "target": "mcp_vet/__init__.py",
  "verdict": "no findings in checked classes",
  "checks_run": ["unsafe-exec", "unsafe-deser", "ssrf", "path-traversal",
                 "zero-auth", "secret-in-code", "audit-record",
                 "unreceipted-allow", "except-returns-success"],
  "files_scanned": ["__init__.py"],
  "files_scanned_count": 1,
  "fixture_test_files_pruned": 0,
  "result": "no findings in checked classes",
  "findings_by_severity": {},
  "record_static": "static: not inferred (grade carries no record_static)",
  "record_dynamic": "runtime: not confirmed (no runner ran)",
  "artifact_digest": "5718f16b57b964baf77087fe2f4221dbff3cb7a546c45f20a174b260987b512c",
  "battery_digest": "e832e75848d5c955bc92ebeecd55156bbd0785312722a956e5d2a099e010cdd7",
  "scanned_at": "2026-09-05T10:40:30Z",
  "fixture_coverage": {
    "available": true,
    "root": "...",
    "files": ["test_checks.py", "test_except_returns_success.py", "..."],
    "per_check": {
      "unsafe-exec": {"must_hit": 25, "must_miss": 8},
      "audit-record": {"must_hit": 11, "must_miss": 0}
      /* ... one entry per check that ran ... */
    }
  },
  "origin_note": "Origin note, September 2026. The \"third verdict\" ...",
  "not_a_certification": "This badge is a self-report of mcp-vet's own checks against this exact artifact on this date. It is not a security certification and no human reviewed this server. Verify the receipt; do not trust the color.",
  "receipt": { "signed": false, "status": "UNSIGNED (--receipt not passed)" }
}
```
(SVG data URI, fixture file list and per-check table trimmed above for
readability; a real run prints the whole thing.)

**The one sentence this badge is allowed to mean, spelled out in the JSON
itself:** *this is a self-report of mcp-vet's own checks against this exact
artifact on this date -- not a security certification, and no human reviewed
this server.* That line, `not_a_certification`, ships in every report rather
than living only in this README, for the same reason `mcp_vet.badge` already
enforces a runnable banned-word gate on every rendered string: a confession
filed somewhere a reader won't see it is not a confession.

What each field is, beyond what its name already says:
- **`checks_run` / `files_scanned` / `verdict` / `result`** -- the governed
  `mcp_vet.badge.BadgeReport` fields: which checks actually ran (read off the
  live registry, never asserted), which files they ran on, and the scan's own
  verdict in its own terms. A **`NO_GRADEABLE_FILES`** verdict (a repo that is
  only tests, only docs, or the wrong language) renders as a distinct **grey**
  badge that says so -- never green, and never the same slate the badge uses
  for an actual clean pass, because "nothing was gradeable" and "we looked and
  found nothing" are not the same claim.
- **`fixture_test_files_pruned`** -- how many otherwise-gradeable files this
  scan excluded because the parity-fixed walk (`select_files` /
  `scan_target`, item 146) classified them as the target's OWN test/fixture
  code, not its shipped product.
- **`fixture_coverage`** -- the grader's OWN proof, not the target's: for each
  check mcp-vet ships, how many places in *mcp-vet's* test suite plant a
  sample that check must fire on (`must_hit`) and one it must stay silent on
  (`must_miss`), read live off mcp-vet's own `test_*.py` files
  (`mcp_vet.fixture_census`). `available: false` means this install is a bare
  wheel with no test files shipped, not that a check has zero fixtures -- the
  two are not the same claim and the field never conflates them. The count is
  a coverage number, not a fixture-quality audit: a test that routes its
  check-name comparison through a shared helper function collapses to one
  count per file rather than one per call site, and `fixture_census.py`'s own
  docstring says so.
- **`origin_note`** -- the origin note from
  `PRODUCT_BRIEF_test_honesty_audit_2026-09-04.md` §8, reproduced verbatim,
  so credit for the third-verdict / wrong-layer-positive-control / borrowed-index
  concepts travels with the free tool rather than living in a file only this
  repo's own contributors ever open.

**`--receipt`** signs the report (`mcp_vet.receipts.sign_grade`, the
`checkpoint-kya-v1-compatible` format documented above) using the persistent
key at a key file the caller names (`receipts.RECEIPT_KEY_FILE`; there is no default path) if provisioned, else
`$MCP_VET_RECEIPT_KEY`, else an ephemeral one-shot key
(`receipts.load_seed()`, batch-100 item 121). The `receipt` field is **always
present and always says which state it is in** -- `"signed": true` with the
`did:key` signer, or `"signed": false` with a `status` starting `UNSIGNED`
and the reason (no `--receipt` flag, no Ed25519 backend installed, or a
malformed provisioned key) -- never a bare crash and never an object that
*looks* signed when it is not. Without `--receipt` at all, `status` reads
`"UNSIGNED (--receipt not passed)"` rather than omitting the field, because a
missing key on a question nobody asked is still worth stating plainly.

**`--sealed`** is the **paid** unit (board item 84): it implies `--receipt`
(a sealed scan with nothing signed makes no sense) and then witnesses that
signed receipt through the [arcaeon connector](../arcaeon_connector)'s
**existing** `ARCAEON_KEY` credit lane -- the same balance and the same
`witness_pin` HTTP call `witness_pin`/`witness_renew` already spend a credit
through. No new billing rail: no Stripe product, no price, no second ledger.
One credit is spent per sealed scan, and only once the ledger append and the
witness pin both succeed -- a failed append, a missing `ARCAEON_KEY`, or an
exhausted balance all refuse with a plain sentence in `sealed_scan.reason`,
never a crash, and never spend a credit. The unsigned free badge above is
never affected by `--sealed` failing or succeeding.

```
$ ARCAEON_KEY=... mcp-vet badge mcp_vet/__init__.py --sealed
...
  "sealed_scan": {
    "sealed": true,
    "ledger_head": {"rows": 1, "chain": "…"},
    "pin": {"ok": true, "status": 201, "endpoint": "https://witness.arcaeon.io/api/pin", "…": "…"}
  }
}
```

**What a sealed scan proves, and what it does not.** A sealed scan proves
that this exact grade existed and was signed at time T by this signer
(`sealed_scan.ledger_head` / the receipt's `signer_did`), and that the signed
record was appended to a hash-chained ledger and witnessed by a third party
that cannot be talked into rewriting its own copy -- so nobody, including us,
can quietly edit or backdate it afterward. **It does not prove that the grade
is correct, and it does not prove that the graded code is safe.** A sealed
scan of a wrong grade is a tamper-evident wrong grade; the signature and the
ledger row attest to *when it was said and by whom*, never to *whether it was
true*. Treat a sealed scan the way you would treat a notarized statement: the
notarization is real and the statement might still be mistaken. See
`not_a_certification` above for the badge's own underlying limit, which a
seal does not lift.

Exit codes: **0** clean, **1** at least one high-severity finding, **3**
`NO_GRADEABLE_FILES` (the scan ran but had nothing to grade -- deliberately
not 0, so a CI gate cannot read "nothing to check" as "checked, and clean"),
**2** the path does not exist, **4** `--sealed` was passed and refused (no
`ARCAEON_KEY`, the connector is not installed, or the credit balance is
zero) -- distinct from 1/2/3 because the free badge above still printed fine
and nothing about the scan itself failed.

## Run it in CI (GitHub Action)

`action/` is a composite action that installs mcp-vet, grades a path, writes the
grade JSON where you can upload it as a build artifact, appends a summary to the
job page, and **exits nonzero on a high-severity finding**.

```yaml
# .github/workflows/mcp-vet.yml
name: mcp-vet
on: [push, pull_request]

jobs:
  grade:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4        # the action does NOT check out for you
      - id: vet
        uses: arcaeon/mcp-vet@v0.0.8
        with:
          path: src/my_mcp_server        # file or directory; default "."
          # warn-only: "true"            # report without failing, for a first run
          # version: "arcaeon-mcp-vet==0.0.15"  # pin it if you want stable answers
      - uses: actions/upload-artifact@v4
        if: always()                     # publish the grade even when it fails
        with:
          name: mcp-vet-grade
          path: mcp-vet-grade.json
```

The action lives in this repo at `action/`; until it is tagged on the Marketplace,
`uses: ./path/to/mcp_vet/action` against a checkout of this repo is the same thing.

| input | default | |
|---|---|---|
| `path` | `.` | File, or directory walked for `*.py`. Vendored trees (`.venv`, `node_modules`, `build`, `site-packages`) are skipped, because a red nobody can fix is how a gate gets switched off. |
| `warn-only` | `false` | Report without failing. A migration setting, not a destination. |
| `output` | `mcp-vet-grade.json` | Where the grade artifact is written. |
| `summary` | `true` | Append the markdown summary to `$GITHUB_STEP_SUMMARY`. |
| `python-version` | `3.11` | Must be >= 3.10. |
| `version` | `mcp-vet` | pip spec. Pin it for reproducible grades. |
| `local-package` | — | Install a checkout instead of the PyPI release. |

Outputs: `verdict`, `grade-path`, `files-graded`, `findings-count`,
`high-severity-count`, `blind-spots-count`.

**Exit codes are the contract.** `0` clean (or warn-only), `1` at least one
high-severity finding, **`2` the scan could not run** — path missing, no Python
under it, mcp-vet not installed. A scan that never happened is deliberately not a
pass and deliberately not a finding: "we found nothing" and "we looked at
nothing" are the two states a gate must never blur. Only **high** fails the job;
medium is heuristic by construction and a gate that reds on a heuristic gets
turned off by its first false positive.

**No checkout, no token, no prompt.** The action reads nothing from the event
payload or the actor, so a bot-triggered push is graded by exactly the same path
as a human's pull request — which is the case that actually matters, since the
agent opening the PR is the one whose server you have not read.

The job summary carries the verdict, the checks that ran, the findings table,
**and the declared blind spots**, because a CI summary that prints only what was
found teaches its reader that green means safe. It doesn't; see the disclaimer
the summary prints every time.

The action's whole body is `action/run_vet.py`, driven by environment variables
so it can be tested off GitHub — `test_action.py` runs it against the planted
credential fixture (asserts red), a clean server (asserts green), a directory, a
missing path, and a broken install, and checks `action.yml` against the script it
calls. An action tested only by pushing to GitHub is an action tested by
strangers.

## Use it as an MCP server
`mcp-vet serve` speaks MCP over stdio and exposes exactly three tools:

- **`mcp_vet_scan(path)`** returns the findings as a list. Each finding carries
  `check`, `severity`, `file`, `line`, `detail`. An empty list means the checked
  classes found nothing — not that the file is safe. `file`/`line` are always
  the SITE: the line you open to see the defect. A finding reached from
  somewhere else adds `via`, a list of `{"file", "line", "handler"}` naming the
  tool handler(s) whose call path gets there (`except-returns-success` only,
  today). One site reached from N handlers is one finding with N routes, not N
  findings. `via` and `gates` are absent, never null, when they do not apply.
- **`mcp_vet_grade(path)`** returns the whole grade artifact the CLI emits,
  `source_sha256` and `blind_spots` included. It returns the artifact rather
  than a verdict string on purpose: a summary is not re-runnable, and
  re-runnable is the only thing this project sells. Feed the result straight
  back to `mcp_vet.grade.verify()`.
- **`mcp_vet_audit_verify()`** recomputes the hash chain over this server's own
  call record and reports `ok` / `rows` / `breaks` / `first_break`. `ok` is
  three-valued and passed through unflattened: `true` (every row verified),
  `false` (a break, named by line), `null` (no break found but the scan was
  bounded). It reads only — it never writes to the ledger it verifies.

### The server records its own calls (v0.0.7)
Every `mcp_vet_scan` / `mcp_vet_grade` call appends **one** hash-chained row to
an [`arcaeon_ledger`](https://pypi.org/project/arcaeon-ledger/) file:
`tool`, ISO-8601 UTC `ts`, `args.path`, **`source_sha256` of the exact bytes
read**, the finding count, and the verdict. A call that fails is recorded too,
with `error` set — an audit trail that only remembers the successes is a
marketing document. Path: `$MCP_VET_AUDIT_LEDGER`, else `~/.mcp_vet/audit.jsonl`,
read at call time.

### Confining what the server may read

This server reads files on request from whatever agent connects to it. By
default it reads any absolute path it is handed, which is the honest default for
the local single-user case it was built for and **not** what you want the moment
it is reachable by a caller you do not control.

Set `MCP_VET_SCAN_ROOT` to confine every read to one subtree:

```
MCP_VET_SCAN_ROOT=/srv/code python -m mcp_vet serve
```

With it set, `../` traversal and symlinks are normalised before the containment
test, and a **relative path resolves against the root rather than the process
working directory**, because otherwise `chdir` would be an escape hatch and the fence
would only hold for callers already behaving. An out-of-root path is refused
identically whether or not the file exists, because a distinct "not found" would
answer questions about the filesystem outside the fence one bit at a time.

It is opt-in, so existing callers passing absolute paths are unaffected. A
security control that arrives as a mystery breakage gets switched off rather
than understood.

`arcaeon-ledger` is an **optional extra**, not a dependency — the scanner core
stays stdlib-only. Without it the server still runs and the record is **OFF**,
but never silently: the status line rides in the server instructions, in every
`mcp_vet_audit_verify` reply, and on stderr at startup.

`mcp_vet_audit_verify` does **not** record itself. A verify that mutates its own
subject cannot report on it cleanly, so one of the three tools sits outside the
trail — which is exactly the per-handler coverage gap listed in the blind spots
below. We sit in our own blind spot knowingly, and there is a test pinning it as
deliberate rather than accidental.

A missing or unreadable path raises rather than returning an empty finding list.
A scanner that answers "no findings" for a file it never opened is a silent
green, which is the failure mode this tool exists to catch elsewhere.

Client config:
```json
{ "mcpServers": { "mcp-vet": { "command": "mcp-vet", "args": ["serve"] } } }
```
Verified 2026-08-30 both ways: an in-process SDK client round-trip in
`test_mcp_server.py`, and the installed `mcp-vet serve` console script driven as
a real stdio subprocess. Works against `mcp` SDK 2.x (`MCPServer`); the 1.x
`FastMCP` name is probed as a fallback but was **not** exercised here — only 2.x
was installed, so treat 1.x support as untested.

**Run it stdio/local only.** See the disclosed exposure below.

## Signed receipts (`mcp_vet.receipts`)

A grade is already re-testable: anyone with the same bytes re-runs it and gets
the same answer. A receipt adds the other half — **attribution and
tamper-evidence** — so a grade can travel without travelling on trust.

```python
from mcp_vet.grade import grade_source
from mcp_vet.receipts import sign_grade, verify_receipt

grade   = grade_source(src, "their_server.py")
receipt = sign_grade(grade)                      # Ed25519 over RFC 8785 canonical JSON
verify_receipt(receipt, grade)                   # True — and it checks the BINDING
```

The signature does not make a grade more correct. A forged grade and a wrong
grade are different problems and this solves exactly one of them.

**What it binds.** The payload carries `source_sha256`, `verdict`,
`checks_run`, `tool_version`, `ts` — and `responseHash`, a `sha256:<hex>` over
the canonical form of the *entire* grade artifact, blind spots included. So the
receipt is small and still pins the whole document. Verify without supplying a
grade and `bound_to_grade` comes back `None`, not `True`: somebody signed *a*
grade is not the same claim as somebody signed *this* one.

**Format: `checkpoint-kya-v1-compatible`, and the suffix is load-bearing.** The
claim names are Checkpoint/KYA-OS's, read off
[`decentralized-identity/kya-os-mcp`](https://github.com/decentralized-identity/kya-os-mcp)'s
SPEC.md — `alg: EdDSA`, `iss`/`sub`/`aud`/`nonce`/`ts`/`requestHash`/
`responseHash`/`outcome`/`prf`, `sha256:<64-hex>` hashes, RFC 8785
canonicalization, self-certifying `did:key` identifiers. KYA positions itself as
*evidence for auditors, not the auditor*, so emitting our grade in its shape
costs nothing and avoids minting a rival format.

But it is **not conformant**, in five ways that ride inside every receipt's
`divergences` field rather than living here where nobody would read them:

1. the envelope is plain JSON, not KYA's detached compact JWS in `_meta.proof`
   — a KYA verifier will not read ours as-is;
2. we sign the canonical payload bytes, not the JWS signing input. Deliberate:
   there is no unsigned protected header for an attacker to swap an `alg` or
   `kid` into, and the key identity lives inside the *signed* payload;
3. session claims (`sessionId`, `scopeId`, `delegationRef`, `clientDid`) are
   absent — a one-shot grade has no session, and a hollow one is theater;
4. no DID document is published anywhere. A verifier learns that **one key**
   signed this, never that it is ours. Trust-on-first-use until we publish one;
5. `source_sha256` / `verdict` / `checks_run` / `tool_version` / `target` are
   mcp_vet extension claims, not KYA names.

**The key.** `$MCP_VET_RECEIPT_KEY` (32-byte seed, base64) first; if unset, the
persistent key file the caller names in `receipts.RECEIPT_KEY_FILE` (no default path; same
32-byte-seed-base64 shape, one line); if that is also absent, ephemeral. An
ephemeral key produces receipts that verify perfectly and attribute to nobody —
fine for a test, useless for a published grade. A malformed env key OR a
malformed file is a loud error, never a silent fall back to ephemeral (a
provisioned-but-corrupt key silently downgrading would be worse than no key).

**Where the persistent key lives and how to rotate it (batch-100 item 121,
2026-09-05).** Same storage convention as arcaeon-verified-snapshot's signing
key: outside the repo entirely (never committed, never logged, never printed —
the code only ever handles raw bytes in memory), under the per-user secrets
directory `~/.arcaeon-secrets/` (an example; any locked-down per-user directory), whose own ACL is already locked to
`NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`, and the one Windows account —
nobody else has a read handle on that directory, so the key file inherits that
lock rather than needing a second bespoke one. To rotate: generate a fresh
32-byte seed and overwrite the file --

```
py -c "import secrets, base64; from pathlib import Path; p = Path.home() / '.arcaeon-secrets' / 'mcp_vet_receipt_signing.key'; p.write_text(base64.b64encode(secrets.token_bytes(32)).decode('ascii') + chr(10), encoding='ascii')"
```

-- then confirm the ACL still matches with `icacls "%USERPROFILE%\.arcaeon-secrets\mcp_vet_receipt_signing.key"` (expect the same three principals as the directory). Every receipt signed under the OLD key still verifies against the `pubkey_b64` it shipped with; rotating changes the identity future receipts sign under, it does not invalidate past ones. There is no key-revocation list here (unlike verified-snapshot's published `active`/`retired`/`revoked` document) because this key's public half is not yet published anywhere — see divergence 4 above. `$MCP_VET_RECEIPT_KEY` in the environment always overrides the file, for the same reason an operator's env var overrides everything else in this module: whoever launches the process gets the final say.

**Optional, and it raises rather than degrades.** Python's stdlib has no
Ed25519, so signing is the `[receipts]` extra (`cryptography`, or `pynacl` via
`[receipts-pynacl]`). Without a backend `sign_grade()` raises
`ReceiptsUnavailable`; it does not hand back an unsigned object shaped like a
receipt. Same rule as the audit trail: the failure worth engineering against is
not a missing control, it is a control somebody *believes* is on.

## Stance
High precision over recall while WIP: a false red on a stranger costs the
reputation this line is built on, so the checker would rather miss than
false-alarm, every finding names its line, and it is judged first on our own
code — where a false positive costs nothing and tunes the tool.

## Self-audit — one row moved, and only one (v0.0.7)

v0.0.6's headline was *we are no longer clean*: the MCP08 `audit-record` class
fired on all four of our own servers, including the one this project ships.
v0.0.7 fixes exactly one of them — ours — and leaves the published record of the
other three exactly where it was. The table is the v0.0.7 snapshot; the current
`self_audit_grades.json` (v0.0.14) has since moved `mcp_public_safety/server.py`
to clean as well, and still holds distill at high and ledger_mcp at medium:

| server | v0.0.6 | v0.0.7 |
|---|---|---|
| `mcp_vet/mcp_vet/server.py` | **high** — no record at all, four gates false | **clean — 0 findings, all four gates met** |
| `mcp_public_safety/server.py` | **high** — no record at all | **high**, unchanged |
| `arcaeon-distill/.../mcp_server.py` | **high** — no record at all | **high**, unchanged |
| `arcaeon_mcp/arcaeon_ledger_mcp/server.py` | **medium** — gate 2 | **medium**, unchanged |

**The first row is the only one that moved, and it moved by keeping a record,
not by pleasing a heuristic.** `mcp_vet_scan` and `mcp_vet_grade` now append a
hash-chained `arcaeon_ledger` row per call, and the gates read:

| gate | evidence in `mcp_vet/server.py` |
|---|---|
| 1 presence | `ledger.append(record)` in `_record_call`, one hop from every handler |
| 2 completeness | `tool`, `ts`, `args` — plus `source_sha256` pinning the bytes read |
| 3 tamper-evidence | the `arcaeon_ledger` import: append-only, hash-chained per row |
| 4 reconstructability | `verify_audit_ledger()`, exposed as a tool **and** as `mcp-vet audit-verify` |

Three of those four could have been bought with a well-named function and an
import, which is why every gate also has a **runtime** test
(`test_audit_ledger.py`): a scan driven through the SDK's in-process client
leaves exactly one row; the row carries all four fields; **a tampered row is
named by line number**; a failed call is recorded rather than vanishing. The
static check is only allowed to go quiet because those pass. Gaming your own
checker is the dishonesty this project exists to catch, and it would have been
easy here.

The fix opened a new gap and it is confessed in the list below rather than
enjoyed: **our gate-1 pass is conditional on an optional import the static pass
cannot see.** In a bare install (`pip install arcaeon-mcp-vet` without `[audit]`) the
write never runs and the file still scores clean.

That `mcp_vet/server.py` row also only exists because the audit set was widened
in v0.0.6: the file had shipped since v0.0.5 and was **never in `scan_own.py`'s
target list**, so the published "all our servers" grade set silently excluded the
one server this project is directly responsible for.

`arcaeon_ledger_mcp` is the reference *presence* pattern and still does not score
clean: gates 1, 3 and 4 read true (a ledger-style append, an append-only
hash-chained library, a `verify` path), but gate 2 reads false, honestly — the
record payload is the caller's dict, so the file itself never guarantees a tool
name or timestamp is in it. The finding names the missing fields rather than
quietly passing the gate.

The six older classes still score **0** on all four servers, and that 0 is
proven non-vacuous the same way it always has been: injecting one
`os.system(user_supplied)` line, or one `sk_live_` literal, into a copy of the
real `mcp_public_safety/server.py` fires at that line. A 0 means "looked and
found nothing," not "did not look." See `self_audit_findings.json`,
`test_checks.py`, `test_audit_record.py` and `test_audit_ledger.py`. Whole suite:
**84 tests** at 2026-08-30 and growing since (run `pytest -q` for the live count;
66 at v0.0.6; two of those were *inverted*, not
deleted, with the old assertion quoted in the docstring).

`arcaeon-distill` moved out of the repo after the first audit, and the locator in
`scan_own.py` / `grade_own.py` quietly stopped matching it — the published grade
set went from three servers to two with no error. It now searches beside the repo
as well and says so out loud when it finds nothing, because an audit that shrinks
in silence is the same failure as a grade that understates its own checks.

## Known blind spots (open right now, each one evidenced)
A checker that hides its gaps is the thing this project exists to catch. So is a
checker that confesses gaps it already fixed: on 2026-08-30 the grade artifact was
still naming three closed gaps as open, which understates the tool and teaches a
reader to discount the whole confession. Both directions are now tested against.

The list below is what is open **today**, and every entry ships with a fixture the
checker scores **0** on plus a control it does fire on, so the confession is
evidenced rather than asserted (`mcp_vet/grade.py: BLIND_SPOT_EVIDENCE`,
`test_grade_metadata.py`). The same list rides inside every grade artifact.

- **Multi-hop taint.** Tool input handed to a local helper that does the read or the
  request is not traced. `mcp_vet/server.py` is the live example — see below.
- **Taint only as a bare name.** `open('/data/' + name)`, `open(f'{name}')`,
  `os.path.join(root, name)` and container subscripts all slip past; only a plain
  parameter name in the argument position counts.
- **Decorator-registered handlers only.** `@mcp.tool()` / `@mcp.resource()` are what
  the tool-input checks enter. A handler registered imperatively
  (`mcp.add_tool(fn)`) is never looked at.
- **Positional parameters only.** Keyword-only parameters, `*args` and `**kwargs`
  are not treated as tool input.
- **The auth test is textual.** It is a whole-file substring scan, so any file
  containing the letters `auth` — the word *author* in a docstring will do it —
  silences the network-transport check completely.
- **The transport must be a literal.** `run(transport=os.environ['T'])` or a splatted
  config dict is invisible, and that is a common deployment shape.
- **Test and publishable keys are never flagged.** `sk_test_`, `pk_test_`, `pk_live_`
  are meant to be hardcoded or meant to be public, so flagging them is noise — but a
  test key promoted to production without being renamed stays invisible.
- **Credentials assembled at runtime.** Two halves added together, a `join`, a base64
  decode: never a single string constant, so nothing matches.
- **The entropy heuristic wants letters and digits.** That gate plus "no whitespace"
  is what keeps prose and fill-me-in placeholders quiet; an all-alphabetic credential
  on a credential-shaped name slips past.
- **A bare AWS secret access key.** It has no prefix to fingerprint, so the 40-char
  shape only counts as the value of an `aws_secret`-shaped name. Bound to any other
  name it is indistinguishable from base64 of anything.
- **The audit gates are per file, not per handler.** A server that records one of
  its tool calls and silently drops the rest passes the presence gate on the
  strength of the one it does record.
- **MCP08 is only asked of a file that both handles and serves.** Handlers in one
  module with `run()` in another are never asked whether they keep a record at all.
  Asking a fragment where its audit trail is would be noise; the cost is this gap.
- **Tamper-evidence is a file-level smell.** Hash-chaining machinery anywhere in
  the module satisfies gate 3, even when the chain covers something other than the
  call record.
- **A call record behind an optional import reads as present.** The write is in
  the source, so the gates pass, but whether it ever runs is decided at install
  time by a dependency no static pass can see. **Our own MCP server is the live
  example** — its trail needs the `[audit]` extra and it scores clean either
  way. Evidenced by two fixtures running the same server, identical but for the
  guarded call: one scores 0, the other fires **high**.
- **Static only.** Runtime behavior, prompt-injection text in tool descriptions, and
  toxic cross-tool flows are out of scope (that is what Snyk Agent Scan does).

### The other direction: findings that may be WRONG (new in v0.0.6)
Everything above is a **miss** — something bad that slips past. MCP08 asks whether
a control is *present*, so it can also fail the opposite way, and a false red is
the more expensive error for a project whose whole asset is not crying wolf at a
stranger. Those get their own evidence table (`FALSE_RED_EVIDENCE`): a fixture
that really does draw the wrong red, plus the reason, tested like everything else.

- **A record written by middleware is invisible.** The presence gate sees only
  records written in this file or in a local helper it calls. A per-call record
  emitted by an imported `@audited` decorator, an ASGI middleware, or the transport
  layer is one import away and unreadable — so a fully audited server is reported
  **high**. This is the worst error this tool can make and it is filed as such.
- **A sink's durability lives in configuration.** A record shipped to syslog,
  journald, a write-once bucket or a managed collector reads as a plain rewritable
  log, so a genuinely append-only pipeline is reported **medium** on gate 3.

Closed and no longer confessed: the `sh -c` list form (v0.0.2), dynamic-import
evasion `__import__('os').system` (v0.0.4), aliased taint (v0.0.4), and tool-input
path traversal, which became a check class of its own (v0.0.4).

### The open blind spot, demonstrated on our own code (2026-08-30, v0.0.5)
Shipping `mcp_vet` as an MCP server produced a clean example of the gap above,
so it is published instead of buried. `mcp_vet_scan(path)` reads whatever file
the caller names — that is a scanner's entire function, so the *exposure* is by
design. What is not by design:

```
$ mcp-vet scan mcp_vet/server.py
0 finding(s)
```

Zero, on a tool handler that opens caller-controlled paths. The taint runs
`path` → `_read(path)` → `read_text`: one hop through a helper function, and
multi-hop taint is exactly what v0.0.4 left open. We did **not** inline the read
to make the checker fire — gaming your own checker is the dishonesty this
project exists to catch. Until the analysis catches up the mitigation is
operational, not analytical: run it over stdio locally, and never bind it to a
network transport without auth in front, which is what our own `zero-auth` check
would tell you.

## Roadmap (aims, not deadlines)
- ~~Give our own MCP server an audit trail~~ — **done in v0.0.7.** It was
  deliberately not done in the change that shipped the check, so the
  self-finding could stand on its own for one version.
- **Close the optional-import gap in gate 1** — the blind spot the fix above
  opened. A record whose sink is guarded by a `try: import` is indistinguishable
  from one that always runs, and the honest fix is probably to *downgrade* the
  gate rather than to detect the guard, since the guard is a legitimate shape.
- Multi-hop taint through helper functions and containers — the gap our own
  server module currently sits in (see above).
- Scanning a real `.env` sitting beside the server. `secret-in-code` reads string
  literals inside the parsed `.py` and nothing else, so a credential in a sibling
  file is invisible to it. That is a line scanner over a non-Python file rather
  than a tree walk, which is why it is a roadmap item and not a quiet extension.
- A second language once the Python surface is solid.
- Public work-in-progress writeup inviting the room to poke holes.
