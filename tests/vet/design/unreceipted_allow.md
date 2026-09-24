# `unreceipted-allow` — PASS verdicts carry no receipt

_Design note, 2026-08-30. Board item D5._

## Why this class and not another

Every check up to this point asks either "can this server be made to do
something dangerous" (unsafe-exec, ssrf, path-traversal, zero-auth) or "is it
leaking at rest" (secret-in-code, MCP01) or "does a tool call leave ANY record
behind" (audit-record, MCP08). This one is narrower and sharper than MCP08: it
looks at a single GATE function that already produces a verdict on both
branches, and asks whether the two branches are receipted the SAME way.

**This is not an OWASP MCP Top 10 number.** MCP01–MCP10 are the ten official
categories; inventing an eleventh and stamping it "MCP11" would be exactly the
overclaim this project's whole pitch argues against (`README.md`'s "honest
caveats"). It sits in MCP08's territory — audit and telemetry — as a specific
bug shape found inside that territory, not a new official category.

## The bug class

A gate/policy function returns a verdict dict on both outcomes. The BLOCK
branch carries a receipt-shaped field (a hash, digest, audit id, signature,
chain link — something a third party could use to prove the refusal
happened). The ALLOW branch does not. Concretely:

```python
def _gate(user, resource):
    if not user.member_of(resource):
        return {"allowed": False, "receipt": _hash(user, resource)}
    return {"allowed": True}                      # <- no receipt
```

This is backwards from what an audit trail is *for*. Nobody needs convincing
that a refusal happened — the caller was told no and stopped. What needs
proving is what was **permitted**: which actions a caller was allowed to take,
when, under what authority. A gate built this way can prove every "no" and
not one "yes." Every permitted action becomes unreplayable while every
refusal is the one thing the system can vouch for — the accountability
burden lands exactly backwards.

## Detection (structural, not semantic)

1. Walk every function/async-function in the file.
2. Collect `return` statements that belong to **that function directly** —
   not to a nested `def`/`lambda` inside it (`_own_returns`). A closure's own
   allow/block story is a different function with a different receipt story.
3. A `Return` counts only if its value is a **dict literal** (`ast.Dict`).
   Read off ONE deliberately-tight field per class (same discipline as
   MCP08's `_TOOL_FIELDS`): a boolean field named
   `allow`/`allowed`/`pass`/`passed`/`permit`/`permitted`/`grant`/`granted`/
   `approve`/`approved`, or a string field named `verdict`/`decision` holding
   an allow- or block-shaped word. Generic names (`ok`, `status`, `result`)
   are deliberately excluded — they get reused for unrelated success/failure
   pairs constantly, and a false gate-classification here is a false red on
   a stranger's file.
4. A dict's receipt-ness is a **key-name** check, not a value check:
   `receipt`/`receipt_id`/`hash`/`digest`/`audit`/`audit_id`/`record`/
   `record_id`/`proof`/`signature`/`hmac`/`chain`/`ledger_id`/`witness`/
   `evidence`/`trace_id`/`audit_hash`.
5. If the function has **at least one allow verdict with zero receipt fields**
   and **at least one block verdict with at least one receipt field**, fire
   one finding per bare-allow return, severity **high**, naming the block
   line it is being compared against.

## What passing looks like

Both branches carry the same receipt field (or neither does — a gate with no
receipts on either side is a different, already-covered gap: `audit-record`
asks whether the server keeps ANY record at all). Symmetric evidence, silence.

## What this cannot see (confessed, evidenced in `grade.py`)

- **Indirection.** The verdict must be a dict LITERAL directly on the
  `return`. `v = {...}; return v` or a constructor (`return
  VerdictResult(allowed=True)`) is invisible even though the runtime
  asymmetry is identical. (`_BS_RECEIPT_INDIRECT`)
- **Cross-function splits.** The allow and block verdicts must be direct
  returns of the SAME function. A gate implemented as two functions or two
  methods — one that grants, a sibling that refuses and receipts the
  refusal — is never compared, because neither one alone has both outcomes
  to compare. This is a common real shape for a permission/cooldown gate.
  (`_BS_RECEIPT_SPLIT`)
- **Static only**, same as every other check here: whether the receipt field
  is ever populated with something verifiable at runtime, versus a decoy
  key with a constant value, is out of scope — this checks *shape*, not
  *content*.

## Proof

`test_checks.py::test_unreceipted_allow_fires_on_bare_pass_receipted_block` —
the reachable red: a toy gate with a receipted block and a bare allow, fires
`high` at the bare-allow line.

`test_checks.py::test_unreceipted_allow_silent_when_both_paths_receipted` —
the firing control: the minimally-different fixture where the allow path also
carries `receipt`; the check stays quiet.

`test_checks.py::test_unreceipted_allow_silent_on_single_outcome_function` and
`test_unreceipted_allow_silent_when_bare_verdict_field_names_generic` cover
the two narrowing decisions above (single-branch functions, generic field
names) so they do not silently erode into false reds later.
