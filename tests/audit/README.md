# arcaeon-audit

**Tamper-evident, audit-ready logs for AI agents.**
*Observability shows you what your agent did. This lets you show it wasn't altered
afterward — the integrity layer under the records your ISO 42001 / SOC 2 auditor and
your enterprise customers' questionnaires already ask you to keep.*

```bash
pip install arcaeon-audit
```

## Why this exists

If you ship an AI agent into anything regulated or enterprise-sold, you're already
being asked to **keep records of what it did and produce them on demand** — by your
**SOC 2** auditor, by **ISO/IEC 42001** (Annex A.6.2.8: keep AI event logs across the
lifecycle), and by the security/AI-governance questionnaires your enterprise customers
send *today*.

**What the law does and does not say, stated carefully because vendors routinely
overstate it.** The **EU AI Act (Article 12)** requires automatic recording of events
for high-risk systems; **it contains no tamper-evidence or integrity requirement**,
and anyone telling you it mandates tamper-proof logging has not read it. The
regulations with teeth on *reconstructibility of records* are elsewhere: **DORA's
technical standards** (financial entities, in force now) require that ICT-related
events be reconstructible after the fact, and the **revised Product Liability
Directive** (applies 9 December 2026) lets courts presume a defect where a defendant
fails to produce evidence within its control. Neither mandates this product. What
they do is make a records gap expensive in a dispute.

The practical gap is simpler than the law: a plain log file proves nothing, because
anyone with write access can edit, delete, or reorder a past record and nothing
shows. When a record is challenged, "we logged it" is a self-report. An append-only,
hash-chained record whose head is checkable by a party you don't control is the
difference between an assertion and evidence.

`arcaeon-audit` is the small, boring layer that gives you exactly that, in two lines
and a folder. It wraps [`arcaeon-ledger`](https://pypi.org/project/arcaeon-ledger/)
(a hash-chained append-only log, zero heavy deps) with an audit-event vocabulary and
an export bundle an auditor can re-verify without trusting you. **It is a mechanism,
not a certification: it makes no one compliant with anything**, and the export's own
summary says so in writing.

## Use

```python
from arcaeon_audit import AuditLog

log = AuditLog("agent-audit.jsonl", system_id="triage-agent-v3", provider="Acme AI")

log.record(event="system_start", agent="triage-agent-v3")
log.record(event="input",  agent="triage-agent-v3", inputs={"patient_msg": "chest pain"})
log.record(event="decision", agent="triage-agent-v3", decision="escalate",
           outputs={"routed_to": "ER", "priority": 1}, capability_version="v2")

log.verify().ok            # True — any edit to history would make this False
log.export_bundle("audit-export/")   # regulator-ready folder
```

`export_bundle()` writes a self-verifying folder:

| file | what it is |
|------|------------|
| `records.jsonl` | the full hash-chained audit log, verbatim |
| `integrity.json` | verdict — `chain_ok`, `truncation_checked`, `truncation_ok`, row count, exact first break if any; a `witness` block naming the witness's `kind` / `identifier` / `independence` + `independence_source` (who decided that label — a self-declaring witness can no longer earn the strongest one by omission) / `self_integrity` (did the witness prove its OWN record unedited); and `how_to_reverify`, a two-step recipe whose second step is a prefilled no-credential call against a **public** witness — the step that does not require trusting us |
| `manifest.json` | system id, provider, period covered, counts by event type |
| `ARTICLE_12_SUMMARY.md` | human-readable mapping to Article 12's requirements |
| `witness.json` | the external-witness pin + truncation verdict + its nature (only when a witness is consulted) |
| `INSTRUMENT_NOTES.md` | the author's own statement of this check's known false positives, known false negatives, and what was not exercised — verbatim, unvalidated (only when `--instrument-notes` / `instrument_notes=` is supplied) |

The bundle is **self-verifying**: `records.jsonl` is hash-chained, so anyone can
re-run `arcaeon-ledger`'s `verify_file()` and reproduce `integrity.json`. Tamper
evidence does not depend on trusting this tool or its author — that's the point.

## Truncation, and why a chain alone can't catch it

A hash chain proves nobody **edited or reordered** your records. It provably
**cannot** prove nobody **truncated** them: delete the most recent rows and the
surviving prefix still chains clean. So a log truncated *before* export would earn
a clean pass from chain verification alone — the one gap the integrity check can't
close by itself.

The fix is an **external witness**: an outside record of your log's head
`(rows, chain)` at a point in time. Pin to it on a cadence; a later truncation has
*fewer* rows than the witness saw, and is caught. `export_bundle()` cross-checks
against the witness when one is configured, and the bundle's verdict distinguishes:

- **`PASS`** — chain intact **and** the witnessed prefix matches the witness: no
  truncation *up to the witnessed head*. The only verdict that claims completeness —
  but only **through the last pin**, and only if the witness is controlled
  **independently** of whoever can write the log. Records written *after* the last
  pin are not covered (pin close to export), and a witness an attacker can also
  rewrite proves nothing.
- **`FAIL`**: the chain itself is broken (an edit, delete, or reorder), named by
  row. Exits 1 whether or not a witness was consulted.
- **`VERIFIED_MODULO_TRUNCATION`** — chain intact, but **no witness was consulted**,
  so truncation was *not* checked. Honest non-proof, never a silent clean pass.
- **`TRUNCATION_DETECTED` / `REWRITE_DETECTED`** — the witness caught missing or
  re-minted history. A positive detection by the witness **outranks** every
  chain-scope verdict below: what the witness saw is evidence, what the local
  chain could not scan is not.
- **`EMPTY_LOG`** — the file is genuinely empty: zero rows, nothing recorded yet.
  An absence of evidence, never an accusation. **Only** for a truly empty file.
- **`UNVERIFIED_SCOPE`** — the log **has records**, but the chain could not speak
  for them (they carry no chain links — the normal state of a log adopted from
  unchained history). Not a pass, not an accusation, an unanswered question.
  Exits **2**, because an unanswered question must never gate CI green.
- **`WITNESS_CHECK_FAILED` / `UNRECOGNIZED_WITNESS_VERDICT:<v>`** — the witness
  consultation could not complete, or returned a verdict this version does not
  know. Reported verbatim rather than mapped onto the nearest accusation.

**Exit codes** (`verify` and `export` share one contract; `verify` never consults
a witness, so on a truncated log it exits `0` where `export --witness` exits `1`):
`0` nothing wrong found · `1` an accusation · `2` the check could not complete.

**`witness.self_integrity`** in `integrity.json` answers a question separate from
independence: did the witness prove **its own record** was unedited? `verified`
only when the witness self-verified its pin chain (arcaeon-ledger 0.5.9+ local
store). Every remote/hosted client exposes only `.latest()` and therefore reads
`unestablished` — the comparison still runs, but a `PASS` resting on it says so
in plain text, because an attacker who can write **both** the log and the pin can
produce exactly that PASS.

**Judge independence yourself.** A witness only proves completeness if it is
controlled *independently* of whoever can write the log. So `integrity.json` names
*what the witness was*: a `witness` block with `kind` (`local_file` / `remote_url` /
`opentimestamps` / `none`), its `identifier`, and an honest `independence` label
(`self_asserted` / `externally_verifiable` / `undeclared` / `none`).

**And it names who decided that label.** `independence_source` is
`established_by_type` (we could tell from the object itself — this outranks any
claim), `self_declared_by_witness` (the witness said so; the `note` is prefixed
SELF-DECLARED and you should verify the identifier yourself), `conservative_default`,
or `no_witness`. A witness that omits `independence` now reads `undeclared`, never
the strongest value — an earlier version defaulted the *other* way, so a shim
wrapping a local file in the log owner's own directory could earn
`externally_verifiable` without its URL ever being contacted. `independence` is the
field a regulator weighs a PASS on; it must not be settable by omission. The reference `WitnessStore` is
a **local file** — same control domain as the log — so it is labelled `self_asserted`,
**not** independent: a PASS backed by it is self-attested, and the block says so
plainly. The point is to let a regulator *see* the independence question, not to claim
an independence we don't have. (Bundles from ≤0.1.3 predate this block; `witness_nature_of()`
reads them back as `kind: unknown`.)

```python
from arcaeon_ledger.witness import WitnessStore, publish_head
from arcaeon_ledger import Ledger

store = WitnessStore("witness.jsonl")            # or a hosted witness endpoint
publish_head(store, "acme/triage-v3", Ledger("agent-audit.jsonl"))   # pin, on a cadence
log.export_bundle("audit-export/", witness=store, witness_namespace="acme/triage-v3")
```

## Instrument defects — the convention

Every checker lies somewhere. A verdict that arrives without an account of where
is asking to be trusted on the strength of its formatting. So `arcaeon-audit`
gives a published result somewhere to put that account, and asks you to fill it:

- **Known false-positive modes** — what makes this check accuse something that is
  actually fine.
- **Known false-negative modes** — what this check would miss even running
  perfectly. (This package ships an obvious one: truncation after the last pin.)
- **What was NOT exercised** — the paths, inputs, and environments this run never
  touched. The likeliest home of the thing that bites you.

The argument is short. A checker that names its own blind spots is more useful
than one that does not, because the second one's silence is indistinguishable
from having none — and nobody has none. It is also, as far as we can tell, not
done anywhere: audit tooling reports verdicts and leaves the limitations in a
chat log, a ticket, or somebody's head. Wherever they live, they are not in the
artefact the auditor reads, which means the artefact overstates itself by
omission. Moving them into the bundle costs one file and buys the one thing a
compliance artefact cannot manufacture: a reason to believe the parts that
aren't hedged.

```bash
arcaeon-audit export agent-audit.jsonl audit-export/ --instrument-notes instrument.md
```

```python
log.export_bundle("audit-export/", instrument_notes=Path("instrument.md").read_text())
```

The notes are embedded **verbatim** — byte-for-byte into `INSTRUMENT_NOTES.md`,
as a string (newlines preserved) into `integrity.json`'s `instrument_notes`,
pinned by `instrument_notes_sha256`, and reproduced under an `## Instrument`
heading in `ARTICLE_12_SUMMARY.md`. The pinned copies are byte-for-byte; nothing
is reflowed, re-wrapped, stripped, or normalised (the summary copy alone follows
the summary file's own line endings): a disclosure edited by the tool reporting
on it is no longer the author's disclosure.

**Contents are never validated.** There is no schema, no required heading, no
lint. The value is the slot existing and travelling with the artefact, not this
tool having an opinion about what belongs in it — and a validator would only
teach people to write whatever passes it.

**Two behaviours worth knowing.** Omit the flag and nothing changes: no new key,
no new file, no warning (bundles from every earlier version keep parsing, and a
nag on every export would only train you to ignore it). Pass the flag at a file
that is missing, unreadable, or not UTF-8 and the export **aborts, exit 2, before
writing anything** — because a bundle that was asked for an instrument block and
shipped without one is indistinguishable from a bundle by an author who was never
asked, and that is precisely the absence-laundered-as-presence this convention
exists to fight.

### Copy-pasteable template

```markdown
## Instrument

**What this check is.** arcaeon-audit <version> — hash-chain verification of
<log>, exported <date>, witness: <kind / namespace / "none consulted">.

**Known false-positive modes** (it accuses, and is wrong)
- Clock skew across writers can order two same-second rows differently than they
  happened; the chain seals the order it was handed.
- A partially-flushed final line reads as an unreadable row, not as a crash.
- <yours>

**Known false-negative modes** (it passes, and something is wrong)
- Truncation after the last pin is invisible: the completeness claim runs only up
  to the witnessed head.
- A witness in the same control domain as the log proves nothing against an
  attacker who can write both.
- Anything the application chose not to log. This tool proves the record was not
  altered; it cannot know what never reached it.
- <yours>

**What was NOT exercised**
- Remote/hosted witness path (only the local store ran).
- <environments, inputs, subsystems this run never touched>
- <yours>
```

Keep it honest and keep it short. A page of hedging reads as a disclaimer; three
specific sentences read as someone who knows their own tool.

## CLI

```bash
arcaeon-audit verify  agent-audit.jsonl
arcaeon-audit pin     agent-audit.jsonl witness.jsonl acme/triage-v3
arcaeon-audit export  agent-audit.jsonl audit-export/ --system-id triage-v3 --provider "Acme AI" \
                      --witness witness.jsonl --namespace acme/triage-v3 \
                      --instrument-notes instrument.md
```

## What this is and isn't

**Is:** an engineering control that produces automatic, tamper-evident, exportable
records — the integrity + export primitive Article 12 leans on.

**Isn't:** legal advice, and not compliance-in-a-box on its own. Article 12
compliance also depends on **what** you choose to log and your broader obligations
under the Act. This tool gives you the hard part (provable integrity + a clean
export); the coverage is yours to define.

## How it works

Every record is hash-chained: `chain = sha256(prev_chain + json.dumps(row_without_chain, sort_keys=True))[:32]`
(first 32 hex chars; Python's default separators, not the compact `json-c14n` form). Edit,
delete, or reorder any record and every later link breaks; `verify()` names the
exact row. Records also carry an `authority` block (principal + capability version)
so "was this edited?" sharpens to "was this edited **and** was the writer authorized?"

MIT licensed. Built by [Arcaeon](https://arcaeon.io) — the evidence layer for AI.
