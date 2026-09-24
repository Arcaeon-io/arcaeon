# arcaeon

<!-- mcp-name: io.arcaeon/arcaeon -->

A record of what an agent did that the agent cannot quietly rewrite, and a way
for anyone who doubts it to check.

Every row your agent writes is hash-chained to the row before it. Change a row,
delete one, or swap two, and the check names the line where the chain breaks.
Hand the file to someone else and they can run the same check without asking
you for anything.

One package. One command: `arcaeon <verb>`.

## Install

```console
pip install arcaeon
```

Python 3.10 or newer. The base install has zero dependencies. That means `pip`
pulls in `arcaeon` and nothing else: no protocol SDK, no crypto library, no
parser. Everything in the Record, Prove and Save lists below runs on the
Python standard library. It also means no network on import. The hosted
verbs open a connection when you run them, and so do a few options that say
so: `proxy --pin-witness`, and `receipt cite`, which looks each citation up
online. Everything else works offline.

The heavy parts are extras. Add only what you use:

| extra | what it adds | what it pulls in |
|---|---|---|
| `arcaeon[mcp]` | `arcaeon mcp` (the MCP server, and `arcaeon mcp --tools`), `vet serve`, `vet probe` | the MCP Python SDK and its dependencies (about 30 packages, including cryptography) |
| `arcaeon[ts]` | vet's TypeScript checks | tree-sitter |
| `arcaeon[sign]` | signed vet reports (`badge --receipt`, and SIGNED rather than UNSIGNED seals), receipt signature checks | cryptography |
| `arcaeon[all]` | all three | all of the above |

```console
pip install "arcaeon[mcp]"
```

## A 60-second first run

Log two rows, check them, change one word of history, check again. These are
POSIX shell lines (on Windows, use Git Bash or WSL, or adjust the quotes).

```console
$ arcaeon log agent.jsonl '{"tool": "search", "query": "weather"}'
<the new row's chain value>
$ arcaeon log agent.jsonl '{"tool": "send_email", "to": "ops"}'
<the new row's chain value>
$ arcaeon verify agent.jsonl
{
 "verdict": "VERIFIED",
 "ok": true,
 "rows": 2,
...
(exit 0)
$ python -c "import pathlib; p = pathlib.Path('agent.jsonl'); p.write_text(p.read_text().replace('weather', 'sunshine'))"
$ arcaeon verify agent.jsonl
{
 "verdict": "BROKEN",
 "ok": false,
...
 "first_break": "line 1: chain mismatch",
...
(exit 1)
```

That is the whole idea. The edit was one word in the first row, and the check
found it and named the line. Exit 0 means VERIFIED. Exit 1 means BROKEN. A CI
gate can use the exit code alone.

What it did not catch: someone deleting the last rows. See Limits below, and
`arcaeon pin`, which is the fix.

## The verbs

Three families. The full reference, with usage lines and examples, is
[docs/VERBS.md](docs/VERBS.md).

### Record: write down what happened

- `log`: add one JSON row to a ledger.
- `verify`: check a ledger's chain. VERIFIED, BROKEN or COULD NOT LOOK.
- `receipt`: issue or check a portable receipt someone else can verify.
- `once`: prove a side effect (a refund, an email) ran once, not twice.
- `proxy`: sit in front of an MCP server and record every tool call.
- `pin`: hand a ledger's current head to a witness, a local file or the hosted one.
- `deal`: a purchase recorded on both sides, step by step.

### Prove: check what was written

- `reconcile`: line up two tapes of the same calls. MATCHED, MISSING, ALTERED or COULD NOT LOOK.
- `audit`: check a log, pin its head, or export it as one bundle.
- `vet`: read an MCP server's source and grade it. No code runs.
- `badge`: a free Markdown badge and JSON report for an MCP server.
- `seal`: the same badge, sealed by the hosted witness. Paid.
- `baseline`: score a fixed probe set before a change and again after.
- `compact`: check a receipt that says what a context compaction dropped.

### Save: spend fewer tokens

- `distill`: cut a tool's output to a token budget and record what was cut.
- `dedup`: drop near-copies from a list of texts.
- `meter`: per-key usage counts and monthly caps for your own tools.

### And

- `stamp`, `credits`, `buy`: the hosted door (below).
- `mcp`: the MCP server (below).
- `selftest`: run every bundled self-check.
- `version`: print the version of the package and each part.

## The hosted door

`stamp`, `pin --remote`, `seal` and `credits` talk to the hosted witness at
witness.arcaeon.io, over HTTPS, and only when you run them. `buy` reads the
offers file bundled with the package and makes no request.

- `arcaeon stamp FILE`: sends the file's sha256 and size, never its bytes.
  Works without a key, inside a free daily allowance.
- `arcaeon pin LEDGER --ns NAME --remote`: records your ledger's head with
  the hosted witness. Needs `ARCAEON_KEY`.
- `arcaeon seal PATH`: grades an MCP server,
  then seals the report. Needs `ARCAEON_KEY` and nothing else, and uses one
  credit. The witness's pin is the seal: it records your ledger's head and
  checks no signature from your machine. With the `arcaeon[sign]` extra and a
  signing key in `MCP_VET_RECEIPT_KEY` the report is also signed and the seal
  says `SIGNED`; on the base install it says `UNSIGNED` and is sealed all the
  same. Without `ARCAEON_KEY` nothing is sent, you still get the free badge,
  and it exits 3. A key pins only under its own namespace prefix; you do not
  need to know yours. If the default namespace is refused, `seal` reads your
  prefix from the refusal (no credit spent) and pins under
  `<prefix>-sealed-scans`. `--ns` still picks one yourself.
- `arcaeon credits`: shows your balance. Needs `ARCAEON_KEY`. Looking is free.
- `arcaeon buy`: prints a checkout link. It opens nothing and takes no card.
  Payment happens on Stripe's page.

`ARCAEON_KEY` is the one setting. Treat it like a password: a leaked key can
pin in your name. For plans and prices, see arcaeon.io/pricing.

## The AI door

```console
pip install "arcaeon[mcp]"
arcaeon mcp
```

`arcaeon mcp` starts the MCP server on stdio. It gives an agent the ledger,
vet and witness tools. `arcaeon mcp --tools` lists them without starting
anything; it needs the `[mcp]` extra too (on the base install it prints the
`pip install 'arcaeon[mcp]'` hint and exits 2).

A note for MCP registry listings: before 0.9, `uvx arcaeon` started this
server. It still does for 30 days after this release, when there is no verb
and stdin is not a terminal. Point your client at `arcaeon mcp` now. The
fallback is removed in 1.0.0.

## Exit codes

One table for every verb.

| code | meaning |
|---|---|
| 0 | good: VERIFIED, MATCHED, a clean grade, or the command did what it said |
| 1 | a bad finding: BROKEN, MISSING, ALTERED, a high-severity grade, a receipt that does not check out |
| 2 | bad usage: the verb could not start on what it was given |
| 3 | COULD NOT LOOK: nothing wrong was found, and not everything could be checked |

3 is never a pass. A gate that treats only 0 as green fails on it, which is
the point.

Before 0.9 some old tools used other codes for the same words (reconcile used
2 for COULD NOT LOOK, for example). For the 0.9.x releases, `--legacy-exit` on
a verb returns the old tool's own code, so a gate wired to it keeps working
while you rewire it. The flag goes away in 1.0.0. MIGRATION.md lists every
code that moved.

## Limits

What a hash chain proves: the rows were not changed in place after they were
written. An edit, a deletion or a reorder in the middle breaks every later
link, and `verify` names the first broken line.

What it does not prove:

- **Truncation.** Cut the most recent rows off and what is left still checks
  out. No chain catches that alone. A pin does: once a witness holds your
  head (row count and chain), a shorter or rewritten log no longer matches it.
- **Truth.** The chain records whatever was written, true or not. To tie a row
  to a fact someone can fetch again, store the fact's digest in the row.
- **Authorship.** Who wrote a row is data in the row, not a signature.
  Someone who rewrites the whole log from the first row can rewrite that too.
  A pin held outside your control is what they cannot move.

What a pin proves: the log was not cut short or rewritten relative to what the
witness saw, and only as of the last pin. The longest gap between pins is your
real exposure. A pin file you keep yourself shows the mechanism works; it is
not an outside party. The hosted witness uses a bearer key, not a signature.

What `reconcile` proves, in its own words:

- MATCHED means two recorders agree; a colluding agent side and tool side can
  write two agreeing tapes of a lie.
- A call that crossed neither instrumented seam leaves no row on either tape;
  an agent that never calls, or calls through an unwrapped channel, is
  invisible here.
- Digests compare content (canonical JSON), not bytes: a meaning-preserving
  re-serialization in transit is MATCHED by design.
- Without a witness pin, both tapes truncated or rewritten in agreement still
  match; a pin bounds that to the rows written after it.

`vet` and `badge` report what their own checks found in the bytes they read.
They are not a review by a person and not a safety certification.

Writing is not fast. Each `log` row (`Ledger.append`) is flushed and synced to
disk before the next one starts, which costs about 18 ms a row on an ordinary
laptop disk: 102,000 rows took about 22 minutes to write. Reading is fast (the
same 50 MB log verifies in about 2.5 seconds).

## Deals

`arcaeon deal` records a purchase made by an agent. The buyer's agent and the
seller each write the same steps (mandate, commit, pay, ship, deliver, cancel)
on their own ledger. Either side, or anyone they hand both files to, can line
them up with `arcaeon deal dispute` and get one verdict: MATCHED, MISSING,
ALTERED or COULD NOT LOOK. The steps and a worked example are in
[docs/DEAL.md](docs/DEAL.md).

## If you used the old packages

Before 0.9 this was thirteen packages: `arcaeon-ledger`, `arcaeon-adapter`,
`arcaeon-receipt`, `arcaeon-audit`, `arcaeon-mcp-vet`, `arcaeon-once`,
`arcaeon-compact`, `arcaeon-continuity`, `arcaeon-baseline`, `arcaeon-dedup`,
`arcaeon-distill`, `arcaeon-meter` and `arcaeon-all`. Each old name gets one
last release that installs `arcaeon` and keeps the old import and the old
command working, with a warning that names the new import. Nothing breaks the
day you upgrade. [MIGRATION.md](MIGRATION.md) has the old and new import and
command for each name, and which exit codes changed.
[shims/README.md](shims/README.md) explains how the old names forward.

## License

MIT. See [LICENSE](LICENSE).
