# Partial credit: what the scanner saw vs what the policy makes of it

Board item M11 (2026-09-02). Question: when the checker finds a recorder but
cannot prove it is reachable from the handler, does that get its own value, or
does it collapse into a pass or a fail?

## The two halves that are currently one field

Today `audit-record` returns a gate 0..4 and a list of findings. The gate is
doing two jobs at once:

1. **Observation.** "A record-writing call exists at file:line; it is N hops
   from the handler; it carries fields X, Y; the chain link is / is not there."
2. **Disposition.** "That is (not) good enough for gate N."

Collapsing them means two strangers who agree on what the code contains can
still disagree with the badge and have nowhere to point. The 9/2 Colony trust
thread named the same split from the other side (`evidence_state` vs
`policy_disposition`): the observation is the part a third party can re-derive
from the bytes; the disposition is the part they can argue with.

## The case for a fifth value

* "Recorder found, reachability uncertain" is a real state. Middleware,
  decorators, imported helpers, base classes: until M1 to M7 land, every one of
  those shapes is a recorder we can see and a path we cannot follow.
* Scoring it 0 says "no record", which is false. Scoring it 1 says "presence
  proven", which is also false.
* Adoption-first pricing means strangers will hit this on day one; a badge that
  calls a decorated FastAPI recorder "gate 0" is the first thing they will
  quote back at us.

## The case against

* Every extra value is a place to hide. "Uncertain" is where a checker goes to
  avoid being wrong, and a badge that says "maybe" is not a badge.
* Gate 0 with a NAMED blind spot already carries the same information without
  a new number; the honest sentence is "we could not follow this shape", and
  that belongs in `blind_spots`, not in the score.
* The benchmark's 30-of-33 gate-0 figure is only comparable across versions if
  the ladder stays four rungs.

## Decision

Keep the four-rung gate as the **disposition** and add the observation as its
own structure rather than a fifth gate value:

```
"audit_record": {
  "gate": 0,                          # policy disposition, unchanged ladder
  "evidence": {                       # what the scanner observed, re-derivable
    "recorder_calls": [{"file":..,"line":..,"kind":"ledger-style ledger.append()","hops":1}],
    "reachable": "no" | "yes" | "unfollowed",   # unfollowed = a shape we cannot walk
    "unfollowed_shape": "decorator" | "import" | "middleware" | "class-method" | null,
    "fields_seen": [...],
    "chain_link_seen": bool
  },
  "blind_spots": [...]
}
```

* `reachable: "unfollowed"` with a named shape is the partial-credit state. The
  gate stays 0 (the policy has no proof), the evidence says exactly why, and a
  stranger reading the JSON can see the recorder we saw.
* The badge draws the gate. The verify page draws the evidence block. They are
  never merged (same rule as M35's static vs dynamic fields).
* When M1 to M7 teach the walker a shape, `unfollowed` for that shape simply
  stops occurring; no ladder change, no re-baselining of the benchmark.

## What this costs

One more structure in the grade JSON (schema bump, so `test_grade_metadata`
must learn it), and the renderer has to show it. It does not change any
existing gate on the fixture corpus; a test should assert that.

## Owed

* Implement `evidence` on the audit-record result once the M1 to M7 walker
  changes land (they are being written in the same session; doing it before
  would mean rewriting it after).
* Renderer: verify page shows `evidence`, badge shows `gate` only.
* Test: fixture corpus gates unchanged before/after the field is added.
