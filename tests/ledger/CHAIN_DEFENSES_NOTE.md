# Chain defenses note (AUDIT-A3, BATCH_500 B-005)

Internal only. Read against `memory/ARCAEON_COMPETITIVE_SCAN_2026-09-10.md`'s
finding: "the hash chain is the thinnest of three free ones" (immudb,
Trillian, Rekor). This is a blunt accounting of which of their standard
defenses `arcaeon-ledger` actually has, on THIS chain, today. No marketing
language. Every line names the file/function it describes, or says plainly
that the file/function does not exist.

## What arcaeon-ledger's chain actually is

`arcaeon_ledger/__init__.py`: a linear, append-only, hash-chained JSONL
file. Each row's `chain` field is `_chain(prev, obj)` — sha256 over the
previous row's chain plus this row's canonicalized content. `verify_file()`
walks every line from genesis and recomputes the chain; `chain_at(path, n)`
recomputes the chain up to row n by the same linear walk. There is no tree
structure anywhere in this module.

## Defense-by-defense

### 1. Client-verifiable inclusion proofs (prove one entry is in the log in O(log n), without holding the whole log)

- immudb: HAS — every read returns a cryptographic proof, verified client-side.
- Trillian: HAS — RFC 6962 Merkle inclusion proofs, the mechanism behind Certificate Transparency.
- Rekor: HAS — the same RFC 6962 shape, on a public instance.
- **arcaeon-ledger: LACKS.** `verify_file()` / `chain_at()` are O(n) linear
  re-walks, not O(log n) proofs. We DO have RFC 6962 Merkle-proof code in
  the codebase — `bridge/arcaeon/rekor_merkle.py` (`verify_inclusion`,
  `verify_consistency`) — but it verifies REKOR's tree, not ours. It is not
  wired to `arcaeon_ledger`'s own chain. BATCH_500 Part 1 Rule 5 already
  names this: "the Merkle batching of our own chain... not today unless
  everything else is done." Until that ships, a stranger who wants to check
  one row without the whole file cannot.

### 2. Consistency proofs (prove tree-of-size-m is a prefix of tree-of-size-n, without full history)

- immudb / Trillian / Rekor: HAS, all Merkle-based, succinct.
- **arcaeon-ledger: LACKS a succinct version.** `witness.py`'s
  `verify_against_witness()` gives the linear equivalent: it recomputes
  `chain_at(ledger.path, w_rows)` against a stored pin. Correct, but O(n)
  per check, and it only checks against OUR OWN witness pin (see #4) — it
  proves nothing to a party who doesn't already trust that pin.

### 3. A public SLO (a stated, monitored availability commitment)

- Rekor: HAS — public instance, 99.5% availability SLO, 24/7 oncall (stated on the project's own pages, per the 9/10 scan).
- immudb / Trillian: no SLO claimed in the scan (self-hosted library shape); N/A rather than a point against arcaeon here.
- **arcaeon-ledger: LACKS.** Nothing in this repo (README.md, witness.py,
  bundle.py) publishes an uptime number or an oncall commitment for the
  hosted witness at `https://arcaeon-witness.vercel.app`
  (`WITNESS_API_BASE` in `bundle.py`). No SLO is stated anywhere in this
  repo, so none should be claimed anywhere else either.

### 4. Independent witnesses (a party outside your own control observing the head)

- Rekor: HAS — Linux Foundation-backed public instance, genuinely third-party to any one user.
- immudb / Trillian: self-hosted by design; independence is on the OPERATOR, not the library — N/A for the library itself.
- **arcaeon-ledger: PARTIAL**, and `witness.py`'s own docstring says so
  before this note has to: "a store you run yourself is NOT the witness
  this module exists to provide" (module docstring, ~line 22). The
  reference `WitnessStore` and the hosted instance at
  `arcaeon-witness.vercel.app` are both operated by Arcaeon, on accounts
  Arcaeon holds — same-party, not independent. What IS independent: pins
  are pushed to a public GitHub repo (`WITNESS_HISTORY_BASE` in
  `bundle.py`, `arcaeon-witness-pins`), so GitHub's commit history and
  clock give a genuine third-party timestamp on WHEN a pin existed —
  though GitHub never checks WHAT the pin says. OpenTimestamps
  (Bitcoin-anchored, per the competitive scan) plays the same role for the
  daily anchor. So: independent on TIME, not independent on CONTENT —
  nobody outside Arcaeon is checking or storing the actual
  chain/row-count claim itself.

### 5. Published checkpoints (periodic signed statements of the current head, held somewhere durable and public)

- Rekor: HAS — Sigstore/Trillian signed-note checkpoints (parsed by our own read-only client's `parse_checkpoint()` in `rekor_client.py`).
- **arcaeon-ledger: PARTIAL.** Each `WitnessStore.record()` call is a
  checkpoint of sorts (rows + chain + as_of, chained to the previous pin
  via `prev`/`self` — `witness.py` ~lines 298-333) and, per `bundle.py`'s
  `WITNESS_HISTORY_BASE`, pushed to a public git repo, giving it a
  durable, publicly-inspectable history. What is missing next to Rekor's
  version: no cryptographic SIGNATURE over the checkpoint (ours is a
  hash-chain, not a signed statement), and the signer/publisher is Arcaeon
  itself, not a disinterested third party.

## The honest summary, three lines, no hedging

- **HAVE:** an honestly-documented linear hash chain with tamper detection
  on the file itself (`verify_file`), a self-chained witness-pin mechanism
  with its own tamper detection (`witness.py`'s `WitnessStore.verify()`),
  a bundled evidence export a stranger can re-run (`bundle.py`), and
  Merkle inclusion/consistency PROOF CODE already in the codebase
  (`rekor_merkle.py`) — currently spent verifying Rekor's log, not ours.
- **LACK:** any Merkle structure on our own chain (so no O(log n)
  inclusion/consistency proofs for arcaeon-ledger rows), any published
  SLO for the hosted witness, and any witness of CONTENT operated by a
  party other than Arcaeon.
- **PARTIAL:** independence is real on TIME (GitHub commit history +
  OpenTimestamps) but not on CONTENT (the only party checking rows+chain
  is Arcaeon's own witness); checkpoints exist and are chained, but are
  not cryptographically signed the way Rekor's are.

## Amendment, 2026-09-13: the publishable-row fence was widened, twice, on purpose

The canon chain's export fence (`bridge/witness/seal_chain.py`, the sibling
chain, not `arcaeon_ledger`'s) refuses to publish a row carrying a field that
is not "a digest, a timestamp, a path or a bounded scalar," because such a
field can carry CONTENT. Two of its checks were widened today. Recorded here
because a fence that gets wider without a paragraph naming what changed is a
fence nobody can audit backwards.

**What was widened.** (1) The `file` path check now admits, besides an
ordinary path, exactly two anchored patterns and nothing else:
`^@liveness/check:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(:retraction)?\Z` and
`^rebreak:[A-Za-z0-9_-]{1,64}:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\+00:00)?\Z`
(`_CHAIN_KEY_SHAPES`). ':' was NOT added to the ordinary path character class.
(2) The `event` enum gained the single member `checked` (`_EVENTS`).

**Why the values are within the fence's own definition of safe.** Each
admitted key is a bounded scalar joined to a timestamp by a colon. The prefix
comes from a two-item vocabulary fixed in code
(`bridge/liveness/reader.py:CHECK_KEY_PREFIX`, `bridge/rebreak/runner.py`'s
fixture ids); the id segment is a code-defined identifier; the tail is an ISO
timestamp. No code path lets a human put free text in any position. `checked`
is likewise a string literal in the two writers that emit it. The fence was
not catching content; it was catching a punctuation mark its character class
had not anticipated, and an enum member nobody had added. Both patterns are
anchored with `\Z` rather than `$`, so a trailing newline does not sneak
through.

**What it cost to leave it.** The export refuses at the FIRST offender, so 22
rows at lines 229-258 made all 278 rows unexportable — the preimage a stranger
needs in order to recompute the chain could not be produced at all. Smoke item
55 had been red on it for four days. Redaction was rejected as an option
because the chain value covers each row's content, so altering a field breaks
the chain at that point; skipping the rows was rejected because a chain with 22
holes is a chain plus a promise. Full three-option costing:
`memory/DECISION_BRIEF_export_prefix_2026-09-13.md`, decided by Fable at 3:10 PM.

**The set is closed and cannot grow.** The writer-side guard landed 2026-09-12
(`_append_chain_row` refuses a key the exporter would refuse) and the liveness
writer now uses the colon-free key `@liveness/check`. Nothing emits either
colon shape any more. Nothing about what may be WRITTEN was loosened.

**gate_drift now watches both.** `seal_chain.publishable_path_key` and
`seal_chain.publishable_event` are registered allowlist gates in
`mcp_vet.gate_drift`, each with a committed corpus that pins the admitted
shapes AND the colon-bearing values that must stay refused (free text, a URL,
`rebreak:` with spaces, each near-miss of an admitted shape, a trailing
newline), plus a committed baseline. Any later edit that moves either accept
set fails CI by naming the exact strings that flipped, in the PR diff. Proven
able to fail: adding ':' to the ordinary path class turns 11 refusal
assertions red in `bridge/tests/test_seal_chain.py` and makes the gate report
DRIFT / WIDENED over 8 named strings.

## What this note is not

Not a redesign, not a roadmap commitment, not a claim about what will
ship. BATCH_500 Rule 5 already scopes the one concrete next step
(Merkle-batch our own chain, reusing `rekor_merkle.py`, "not today unless
everything else is done") and gates it AUDIT-A3, first ten proofs read by
Fable. This note states where the gap actually is, in our own function
names, so nobody re-derives it from the competitive scan a second time.

---
Reader: Fable's Monday A3 pass; feeds queue tasks 041/043 per the item's own note.
