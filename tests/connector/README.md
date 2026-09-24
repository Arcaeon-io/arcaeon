# arcaeon

**One MCP connector for the whole Arcaeon toolbox.** Install once, wire one
stanza into your client, get eleven tools: a tamper-evident agent ledger, a
static checker for MCP-server source, and the hosted witness that catches
truncation.

Free to install. Free to use, except the two tools that spend money on our side,
and those tell you the price in plain English instead of failing.

Arcaeon ships a shelf of small single-purpose packages. A shelf is a
distribution problem: an agent that would use three of them has to find three,
install three, and wire three stanzas. Most never get past the first. This is
the one door.

---

## Install

```bash
pip install arcaeon
```

All three packages are on PyPI (`arcaeon` 0.1.3, `arcaeon-ledger` 0.7.3,
`arcaeon-mcp-vet` 0.0.15 as of 2026-09-02; `pip index versions <name>` for the
current release), so that one line is the whole install.
The dependency pins (`arcaeon-ledger>=0.7.0`, `arcaeon-mcp-vet>=0.0.8`) are the
versions the agent tools actually live in, declared as such rather than loosened:
a pin that installs and then fails at import is worse than a resolver error that
says what is missing.

Working from a checkout instead:

```bash
pip install -e path/to/arcaeon-ledger
pip install -e path/to/mcp_vet
pip install -e path/to/arcaeon_connector   # this package
```

Check the install without starting a server:

```bash
arcaeon-mcp --tools
```

## Wire it into a client

`.mcp.json` (Claude Code and friends):

```json
{
  "mcpServers": {
    "arcaeon": {
      "command": "arcaeon",
      "args": ["mcp", "--log", "agent.log.jsonl"],
      "env": {}
    }
  }
}
```

With the paid lane switched on, and the ledger somewhere deliberate:

```json
{
  "mcpServers": {
    "arcaeon": {
      "command": "arcaeon",
      "args": ["mcp", "--log", "state/agent.log.jsonl", "--ns-dir", "state/ledgers"],
      "env": {
        "ARCAEON_KEY": "your-witness-key"
      }
    }
  }
}
```

If your client cannot run console scripts, `"command": "python", "args": ["-m",
"arcaeon.mcp"]` is the same server.

## The tools

| Tool | Cost | What it does |
|---|---|---|
| `ledger_append` | free | Append one action record to a hash-chained log; returns its chain hash. |
| `ledger_verify` | free | Verify the chain. Three-valued: `true` every row verified, `null` the scan was bounded (**not a green**), `false` names the exact broken line. |
| `ledger_prove_my_conduct` | free | Log a batch to your own named ledger, get back one head hash to hand your principal. |
| `ledger_verify_peer_ledger` | free | Judge ANOTHER agent's exported log from its text alone. No access to their machine, no writes on yours. |
| `ledger_declare_break` | free | Your log broke. Name the break instead of re-minting a chain that verifies. |
| `vet_scan` | free | Statically scan a Python MCP server's source; findings with exact line numbers. |
| `vet_grade` | free | The full re-testable grade artifact: `source_sha256`, findings, checks run, declared blind spots, verdict. |
| `vet_audit_verify` | free | Recompute the hash chain over mcp-vet's own call-record ledger; three-valued `ok`, `rows`, `breaks`, `first_break`. |
| `witness_pin` | **paid** | Pin your ledger head with a party you cannot advance. The only thing that catches truncation. |
| `witness_renew` | **paid** | Restate an unchanged head so a finished log stops looking abandoned. |
| `arcaeon_status` | free | Versions, the free/paid split, whether a key is set, where the ledger is. |

Names are prefixed by which product answers: `ledger_*`, `vet_*`, `witness_*`.

### Calls through the connector land in the audit ledger

`vet_scan` and `vet_grade` write to mcp-vet's own tamper-evident call-record
ledger the same way a call to mcp-vet's standalone server would — this
connector does not scan or grade code with its own logic, it calls
`mcp_vet.server.scan_recorded` / `grade_recorded`, the recording entry points,
not the plain `scan_source` / `grade_source` that skip the ledger. `vet_audit_verify`
reads and recomputes that same shared ledger, so a caller can check the record
was not tampered with. This was a real bug once (an earlier version of this
connector called the non-recording functions, so a vet call made through the
connector left no row while the identical call through mcp-vet's own server
did — see `server.py`'s module docstring), and three tests in `test_connector.py`
exist specifically to keep it caught:

- `test_vet_scan_through_the_connector_is_recorded_in_mcp_vets_ledger`
- `test_vet_grade_through_the_connector_is_recorded_too`
- `test_vet_audit_verify_reads_the_shared_audit_ledger`

That is the extent of the claim: calls are recorded, and the record is
checkable. It says nothing about whether the scan or grade itself was correct
— see "What this does NOT prove" below.

### The connector's own call record (0.1.4, unreleased)

Everything above is about somebody else's record: the caller's ledger, or
mcp-vet's. Until 0.1.4 the connector kept none of its own, and mcp-vet's
`audit-record` check said so (gate 0 of 4, 2026-09-02). Now every one of the
eleven tools, this status tool included, appends one row to a hash-chained
JSONL at `ARCAEON_CALL_RECORD` (default `arcaeon.calls.jsonl` beside the
ledger log): tool name, UTC timestamp, a sha256 digest of the arguments (the
digest, never the arguments; `ledger_append` carries your conduct records and
the call record must not become a copy of them), whether the call succeeded,
and the error text when it did not. The row is written after the tool runs,
so a failed call is recorded as a failure, not as a success that happened to
raise. The file is in arcaeon-ledger's format, so `arcaeon-ledger verify`,
`verify_call_record()` in `server.py`, or the connector's own
`ledger_verify_peer_ledger` tool all recompute it. `test_call_record.py`
holds the six tests, including one that drives every tool once and asserts
eleven rows with eleven names.

## The paid lane

Two tools need `ARCAEON_KEY`, because a hosted pin is a commit somebody pays
for. Called without a key they return a plain sentence:

```
witness_pin is a paid Arcaeon tool and no ARCAEON_KEY is set, so nothing was sent.

It pins your ledger head with the hosted witness (https://witness.arcaeon.io): a
party you cannot advance, which is the only thing that catches truncation.

Free tier: 100 pins/month, no card. To get one: email hello@arcaeon.io or ask
Nora for a key.
Entry pack: $5 for 1,000 pins ($0.005/pin): https://buy.stripe.com/aFa4gAb10ead3xy35f0RG08
...
```

No stack trace, no silent nothing, and the free door named before the paid one —
the witness free tier is 100 pins/month with no card, and the witness library
itself is self-hostable free forever (point `ARCAEON_WITNESS_URL` at your own
deployment and the same two tools work). The catalog those numbers come from is
[`/.well-known/offers.json`](https://arcaeon.io/.well-known/offers.json), and a
test in this repo fails if the copy in the code drifts from it.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `ARCAEON_KEY` | unset | Witness bearer key. Unset means the two paid tools explain themselves instead of running. |
| `ARCAEON_LEDGER_LOG` | `agent.log.jsonl` | The ledger `ledger_append` / `ledger_verify` write. Same as `--log`. |
| `ARCAEON_LEDGER_NS_DIR` | `ledgers/` beside the log | Per-namespace agent ledgers. Same as `--ns-dir`. |
| `ARCAEON_CALL_RECORD` | `arcaeon.calls.jsonl` beside the log | The connector's own hash-chained record of every tool call (0.1.4). Same variable the other Arcaeon servers honour. |
| `ARCAEON_WITNESS_URL` | `https://witness.arcaeon.io` | Point the witness tools at your own self-hosted deployment. |
| `LICENSE_GATE_REQUIRED` | unset (off) | Set to `1` to also require a license key on the two paid tools. Off by default; see below. |
| `ARCAEON_LICENSE_KEY` | unset | The license key, when the gate is on. Bound to a ledger namespace, not to a machine. |
| `LICENSE_GATE_MODULE` | auto | Override which module implements the gate. Only useful to a self-hoster or a test. |

## The optional license gate (off by default)

A second, optional gate sits in front of the same two paid tools and answers a
different question: not "does this caller have a witness account" (that is
`ARCAEON_KEY`) but "is this copy of the package licensed". It is **inert unless
you set `LICENSE_GATE_REQUIRED=1`** - unset, nothing here imports, nothing here
runs, and the connector behaves exactly as it did before this existed.

When it is on, the license is bound to the **ledger namespace being pinned**.
That is the whole idea: a borrowed key would have to pin under the lender's
namespace, into the lender's public pin history, under the lender's name. The
gate does not prevent that; it makes it self-incriminating, which for people
who buy audit tooling is the part that bites.

It **fails closed**. `LICENSE_GATE_REQUIRED=1` with no gate module installed
refuses the paid tools rather than waving them through, because a required
check that passes because its own implementation is missing looks enforced and
is nothing.

Honest limit, stated here as well as in the gate's own README: a client-side
license check deters, it does not prevent. Anyone who can edit the package can
delete the call. The real moat is updates and the ledger identity, not this.

## What this does NOT prove

Inherited from the packages it bundles, restated here because a bundle that
drops the caveats is selling a stronger claim than its parts:

- **Tamper-evidence is not truth.** The ledger proves a record was not altered.
  It says nothing about whether what it records was correct, or whether the
  agent that wrote it was honest at the time.
- **A clean `vet_scan` is not "safe".** It means a small set of documented
  failure classes found nothing. mcp-vet publishes its own blind spots inside
  every grade, including one it demonstrates on its own server.
- **A pin proves no-truncation only relative to what the witness saw, and only
  as recently as the last pin.** The pin gap is the security parameter.
- **Witness auth is bearer-key only** (`auth_level: "bearer-stage0"`). A leaked
  key can pin and renew in your name. Owner-signature auth is designed
  (STAGE1_SIGNATURE_DESIGN) and not built.
- **This connector adds no analysis of its own.** It re-exports; the ledger
  tools dispatch straight into `arcaeon_ledger.mcp_server.handle`, the same
  function the standalone server runs. If a result here disagrees with the
  standalone server, that is a bug in this package, and one of the tests exists
  to catch exactly that shape of drift.

## Run the tests

```bash
pip install -e ".[dev]"
pytest -q
```

Thirty-one tests as of 2026-09-02 (re-run `pytest -q` for the current count;
this README does not re-derive it, so treat the number as a snapshot, not a
promise). Most drive a real MCP round-trip; one of them spawns the installed
entry point as a subprocess and speaks raw JSON-RPC down the pipe, because
"one install and it works" is a claim about the package, not about an
importable module.

## Security note

Local stdio only. The tools read caller-named paths, so do not put this behind a
network transport without an auth layer in front — which is what `vet_scan`'s
own `zero-auth` check would tell you about anyone else's server.

MIT licensed. Every product Arcaeon charges for is listed in
[`/.well-known/offers.json`](https://arcaeon.io/.well-known/offers.json); a
charge that is not in that file is not ours.

## More

- [arcaeon.io/ai](https://arcaeon.io/ai) — the agent-facing side of the site:
  product statuses, verbatim review receipts, and how to verify a claim
  yourself instead of taking it on trust.
- [arcaeon.io/ledger](https://arcaeon.io/ledger) — the standalone ledger's own
  docs (what it proves, what it doesn't, the three-valued `verify()` contract).
