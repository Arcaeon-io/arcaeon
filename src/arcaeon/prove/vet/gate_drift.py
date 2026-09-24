"""mcp_vet.gate_drift — the differential accept-set check for pattern gates
(task 073, spec: memory/FINDING_regex_gate_drift_is_a_real_check_class_2026-09-12.md).

THE CLASS THIS CATCHES (from the spec, restated because it is the whole
reason this file exists): a regex-based gate — a DETECTOR that must match bad
things, or an ALLOWLIST that must match only good things — drifts silently
when someone edits the pattern. A tightened detector quantifier stops
catching real positives (narrowing). A widened allowlist prefix starts
admitting things it used to refuse (widening). Either edit passes every
existing unit test, because those tests name specific inputs and the defect
lives in the *boundary between* named inputs. The fix is not "test the
pattern harder" — it is to diff the pattern's ACCEPT SET (the corpus strings
it currently matches) against the accept set recorded last time, and report
every string whose classification FLIPPED, in both directions, separately.
A flip is not automatically a bug — the finding calls it "a declaration
requirement, not a failure" — but it must never be silent.

--------------------------------------------------------------------------
WHO FEEDS THE CORPUS, FROM WHERE, ON WHAT CADENCE (read this before trusting
this module's silence — the task this file was built under is explicit that
an instrument nobody feeds is worse than no instrument):

  WHERE: one corpus file per registered gate, hand-written, at
  `tests/fixtures/gate_drift/<gate_name>.corpus.json` — a flat JSON list of
  strings. Sits next to `tests/fixtures/secret_in_code_server.py` and
  `tests/fixtures/recorders/`, this project's existing home for planted
  positive/negative fixtures (test_secret_in_code.py's own docstring already
  promises "the corpus for the secret detectors already exists in checks.py's
  own fixtures" — this module's corpora were seeded from exactly those, not
  invented fresh).

  WHO WRITES IT INITIALLY: whoever adds a new registered gate (a developer
  touching `_VENDOR_SHAPES`, `_BANNED_RE`, `_PUBLIC_PREFIXES`, or any other
  pattern worth protecting) is the one who names the gate, writes its corpus,
  and runs `--update-baseline` once to record the starting classification.
  That is a human, by hand — exactly the answer the task calls "acceptable
  ONLY if something scheduled reminds them."

  THE SCHEDULED REMINDER (the part that makes the hand-written answer
  acceptable, not a check that cannot fail): `test_gate_drift.py`'s
  `test_registered_real_gates_are_clean_against_committed_baseline` runs
  every time the mcp_vet suite runs, and the suite is not optional — GitHub
  Actions runs it on every push and every pull request that touches
  `projects/mcp_vet/**` (`.github/workflows/mcp_vet-tests.yml`, confirmed
  2026-09-13). So the cadence is "every commit that touches this package,"
  the same cadence every other test in this suite already runs on. If a
  developer edits `_VENDOR_SHAPES` (or any other registered pattern) and the
  accept set over the committed corpus moves, CI goes red on this test —
  not on a vague "something might be different" red, but on a message naming
  the exact strings that flipped and which direction. The fix is
  `python -m arcaeon.prove.vet.gate_drift --update-baseline`, which rewrites the
  baseline file; committing THAT diff, in the same PR as the pattern edit, IS
  the declaration the finding calls for — a reviewer sees exactly which
  strings changed classification, in the PR diff, in plain sorted JSON.

  THE HONEST GAP, NAMED RATHER THAN SHIPPED QUIETLY: the scheduled reminder
  above only fires when an EXISTING corpus string's classification changes.
  Nothing is scheduled to prompt a developer to ADD a new corpus string when
  a genuinely new case appears — a new vendor key format, a newly-discovered
  false positive, a new banned word someone almost added to copy. That
  growth still depends on a human noticing and typing it in, unprompted, the
  same as any other test-fixture gap in this codebase. This project already
  runs a self-audit pass over its own MCP servers (`scan_own.py`,
  `grade_own.py`) — folding "does every registered gate's corpus still
  reflect this file's own vocabulary" into that pass would close the gap, but
  that wiring does not exist yet. Recorded here so it does not quietly read
  as solved.

  STALE/EMPTY CORPUS: `check_gate` never reports "no flips" when it has
  nothing to compare. An empty or missing corpus file returns status
  `no_coverage`, not `ok` — a gate with `no_coverage` is exactly as unproven
  as one with no check at all, and the CLI/test surface it as a distinct,
  non-passing state. A corpus that exists but has no baseline yet (first run
  after registering a gate) returns `no_baseline`, also not `ok`.
--------------------------------------------------------------------------

USAGE
  As a named mcp_vet gate:      check_gate("checks.secret_stripe_live_key_shape")
  Against an ad-hoc pattern:    register_gate("my.gate", "detector", lambda: my_pattern, "...")
                                 then check_gate("my.gate", corpus=[...])
  From the command line:        python -m arcaeon.prove.vet.gate_drift            (check all, exit>0 on any non-ok)
                                 python -m arcaeon.prove.vet.gate_drift --list
                                 python -m arcaeon.prove.vet.gate_drift NAME --update-baseline
"""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union

from . import badge as _badge
from . import checks as _checks

Matcher = Callable[[str], bool]

STATUS_OK = "ok"
STATUS_DRIFT = "drift"
STATUS_NO_BASELINE = "no_baseline"
STATUS_NO_COVERAGE = "no_coverage"

# arcaeon merge: the corpora moved with vet's tests to <repo>/tests/vet/tests/fixtures.
_FIXTURE_ROOT = (Path(__file__).resolve().parents[4] / "tests" / "vet" / "tests"
                 / "fixtures" / "gate_drift")

# Human-facing framing for a flip, keyed by gate kind. The check reports every
# flip regardless of kind; this only decides which direction gets called out
# as the dangerous one in the message text.
_DIRECTION_LABELS = {
    "detector": {
        "gained": "widened (now ALSO flags these — usually a genuine broadening; confirm it was intended)",
        "lost": "NARROWED — used to catch these, now silently escapes",
    },
    "allowlist": {
        "gained": "WIDENED — now silently admits these",
        "lost": "narrowed (used to admit these, now refused — usually a safe tightening; confirm it was intended)",
    },
}


def as_matcher(obj) -> Matcher:
    """A gate's live pattern is either a compiled regex (search-anywhere, the
    shape every gate in badge.py/checks.py already uses) or a callable(str)->
    bool (the shape `_is_public_shape` uses for the prefix-tuple allowlist).
    Both are first-class here — the check does not care how a gate decides,
    only that it can be asked."""
    if isinstance(obj, re.Pattern):
        return lambda s: obj.search(s) is not None
    if callable(obj):
        return obj
    raise TypeError(
        "gate matcher must be a compiled re.Pattern or a callable(str)->bool, "
        f"got {type(obj)!r}")


@dataclass(frozen=True)
class GateSpec:
    name: str
    kind: str                      # "detector" or "allowlist"
    get_matcher: Callable[[], object]   # zero-arg; re-reads the live pattern/
                                          # callable from its source module
                                          # every call, so a monkeypatch of the
                                          # underlying module attribute (e.g. in
                                          # a sabotage test) is observed without
                                          # this registry needing to know.
    note: str = ""

    def __post_init__(self):
        if self.kind not in ("detector", "allowlist"):
            raise ValueError(f"gate kind must be 'detector' or 'allowlist', got {self.kind!r}")


GATES: Dict[str, GateSpec] = {}


def register_gate(name: str, kind: str, get_matcher: Callable[[], object], note: str = "") -> GateSpec:
    spec = GateSpec(name=name, kind=kind, get_matcher=get_matcher, note=note)
    GATES[name] = spec
    return spec


def resolve_matcher(gate: GateSpec) -> Matcher:
    return as_matcher(gate.get_matcher())


def accept_set(matcher: Matcher, corpus: List[str]) -> List[str]:
    """The subset of `corpus` the matcher currently accepts (matches), sorted."""
    return sorted(s for s in corpus if matcher(s))


# --- corpus / baseline I/O ----------------------------------------------------

def _corpus_path(name: str) -> Path:
    return _FIXTURE_ROOT / f"{name}.corpus.json"


def _baseline_path(name: str) -> Path:
    return _FIXTURE_ROOT / f"{name}.baseline.json"


def load_corpus(name: str) -> List[str]:
    """[] (never an error) when the file is missing or empty — the caller
    (`check_gate`) is the one place that turns "nothing to compare" loud."""
    p = _corpus_path(name)
    if not p.exists():
        return []
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{p}: corpus file must be a JSON list of strings")
    # de-dup, preserve first-seen order
    seen = []
    for s in data:
        if not isinstance(s, str):
            raise ValueError(f"{p}: corpus entries must be strings, got {s!r}")
        if s not in seen:
            seen.append(s)
    return seen


def load_baseline(name: str) -> Optional[Dict[str, bool]]:
    """None means 'no baseline recorded yet' — distinct from an empty dict,
    which would mean a baseline was recorded against an empty corpus (itself
    only reachable by hand-editing the file, since `write_baseline` refuses
    to run against an empty corpus from the CLI)."""
    p = _baseline_path(name)
    if not p.exists():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{p}: baseline file must be a JSON object of string->bool")
    return {k: bool(v) for k, v in data.items()}


def write_baseline(name: str, mapping: Dict[str, bool]) -> Path:
    """Sorted keys, 2-space indent, trailing newline — a one-line-per-entry
    diff in git, so a PR that moves a pattern shows exactly which corpus
    strings flipped, in either direction, in the review itself."""
    _FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
    p = _baseline_path(name)
    p.write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


# --- the check itself ---------------------------------------------------------

@dataclass
class DriftReport:
    gate: str
    status: str                # ok | drift | no_baseline | no_coverage
    gained: List[str] = field(default_factory=list)
    lost: List[str] = field(default_factory=list)
    new_corpus_entries: List[str] = field(default_factory=list)
    message: str = ""


def check_gate(name: str, corpus: Optional[List[str]] = None) -> DriftReport:
    """Compute the gate's current accept-set over `corpus` (or its recorded
    corpus file when `corpus` is None), diff it against the stored baseline,
    and report every flip in both directions by name. Never returns `ok` when
    there was nothing to compare — see the module docstring."""
    gate = GATES.get(name)
    if gate is None:
        raise KeyError(f"no such registered gate: {name!r} (known: {sorted(GATES)})")

    if corpus is None:
        corpus = load_corpus(name)
    else:
        corpus = list(dict.fromkeys(corpus))

    if not corpus:
        return DriftReport(
            gate=name, status=STATUS_NO_COVERAGE,
            message=(
                f"corpus is EMPTY (or missing at {_corpus_path(name)}) — this gate "
                "has zero test input and cannot observe a drift in either "
                "direction. This is reported as NO COVERAGE, never as 'no "
                "flips': a check with nothing to compare cannot fail, which is "
                "worse than no check."))

    matcher = resolve_matcher(gate)
    current = {s: bool(matcher(s)) for s in corpus}

    baseline = load_baseline(name)
    if baseline is None:
        return DriftReport(
            gate=name, status=STATUS_NO_BASELINE,
            new_corpus_entries=sorted(current),
            message=(
                f"no baseline recorded yet for {name!r} (expected at "
                f"{_baseline_path(name)}). Confirm the current classification of "
                "every corpus string by hand, then run "
                "`python -m arcaeon.prove.vet.gate_drift --update-baseline`. Until then "
                "this gate has a corpus but no memory — the same blindness as "
                "no corpus, one run later."))

    gained: List[str] = []
    lost: List[str] = []
    new_entries: List[str] = []
    for s, verdict in current.items():
        if s not in baseline:
            new_entries.append(s)
            continue
        old = baseline[s]
        if verdict and not old:
            gained.append(s)
        elif old and not verdict:
            lost.append(s)

    status = STATUS_DRIFT if (gained or lost) else STATUS_OK
    labels = _DIRECTION_LABELS[gate.kind]
    parts = []
    if gained:
        parts.append(f"{labels['gained']}: {sorted(gained)}")
    if lost:
        parts.append(f"{labels['lost']}: {sorted(lost)}")
    if new_entries:
        parts.append(
            f"{len(new_entries)} corpus entr{'y is' if len(new_entries) == 1 else 'ies are'} "
            f"not yet in the baseline (uncompared, not a flip): {sorted(new_entries)}")
    message = "; ".join(parts) if parts else "no change — accept-set matches the recorded baseline"

    return DriftReport(gate=name, status=status, gained=sorted(gained),
                        lost=sorted(lost), new_corpus_entries=sorted(new_entries),
                        message=message)


def update_baseline_from_corpus(name: str) -> DriftReport:
    """Recompute the baseline from the CURRENT code + CURRENT corpus and
    overwrite the baseline file. Refuses (returns no_coverage, writes
    nothing) on an empty corpus — you cannot declare a baseline for a gate
    with no test input."""
    corpus = load_corpus(name)
    if not corpus:
        return DriftReport(gate=name, status=STATUS_NO_COVERAGE,
                            message=f"corpus is EMPTY at {_corpus_path(name)} — refusing to write a baseline from nothing")
    matcher = resolve_matcher(GATES[name])
    mapping = {s: bool(matcher(s)) for s in corpus}
    write_baseline(name, mapping)
    return DriftReport(gate=name, status=STATUS_OK,
                        message=f"baseline written for {len(mapping)} corpus entries")


# --- real, named gates in mcp_vet ---------------------------------------------
# Each `get_matcher` is a zero-arg lambda that looks the pattern up on its
# SOURCE MODULE at call time (never captures the object at import time), so a
# `monkeypatch.setattr(badge, "_BANNED_RE", ...)` in a test is exactly as
# visible to this registry as an edit committed to badge.py would be — that
# equivalence is what lets the sabotage tests prove this check can fail.

def _vendor_shape_pattern(label: str) -> re.Pattern:
    for l, pattern in _checks._VENDOR_SHAPES:
        if l == label:
            return pattern
    raise KeyError(f"no vendor shape registered under label {label!r}")


register_gate(
    "badge.banned_verdict_words", "detector",
    lambda: _badge._BANNED_RE,
    "badge.py _BANNED_RE: verdict words (certified/safe/secure/trusted/...) a "
    "badge must never carry. Narrowing this (dropping a word) lets a banned "
    "verdict back into a published badge silently.")

register_gate(
    "badge.runtime_claim_words", "detector",
    lambda: _badge._RUNTIME_CLAIM_RE,
    "badge.py _RUNTIME_CLAIM_RE: words claiming runtime confirmation "
    "(observed/confirmed/runner/launched/executed) that must never appear in "
    "the STATIC line of a badge. Narrowing lets a static-only claim read as "
    "runtime-confirmed.")

register_gate(
    "checks.secret_stripe_live_key_shape", "detector",
    lambda: _vendor_shape_pattern("Stripe live secret key"),
    "checks.py _VENDOR_SHAPES: the Stripe live secret key prefix+length "
    "shape. This is the exact pattern the spec finding uses as its worked "
    "example (tightening {24,} to {32,} silently stops flagging real "
    "28-character keys).")

register_gate(
    "checks.secret_public_prefix_exemption", "allowlist",
    lambda: _checks._is_public_shape,
    "checks.py _PUBLIC_PREFIXES via _is_public_shape: prefixes exempted from "
    "secret-in-code flagging as test/publishable-shaped. Widening this "
    "(adding a prefix) makes a real-looking key silently stop being flagged.")


# --- gates on a pattern OUTSIDE this package ----------------------------------
# `bridge/witness/seal_chain.py` is a sibling in the same private monorepo (that
# repo is the git root; projects/mcp_vet is a member with its own pyproject --
# see .github/workflows/mcp_vet-tests.yml, which checks out the whole repo and
# only sets working-directory). Its publishable-row fence is exactly the kind of
# pattern this module exists to watch: an ALLOWLIST that decides what may leave
# the house in a public export, widened by a recorded decision on 2026-09-13
# (memory/DECISION_BRIEF_export_prefix_2026-09-13.md). Registering it here is
# the condition that made that widening reviewable instead of quiet.
#
# The import is LAZY and happens inside the matcher, not at module import, for
# two reasons: this package is also published as a standalone wheel where
# `bridge` does not exist, and `check_gate` returns NO_COVERAGE on a missing
# corpus BEFORE it ever resolves a matcher -- so in a wheel install these two
# gates report "no corpus", which is honest, rather than exploding on import and
# taking the other four gates with them.

def _seal_chain():
    import sys as _sys
    # PRIVATE PIECE, not in this package: seal_chain lives in the private repo's
    # bridge/. Reached only when ARCAEON_VET_PRIVATE_ROOT names that checkout;
    # otherwise the import below fails and the two seal_chain gates report that.
    root = os.environ.get("ARCAEON_VET_PRIVATE_ROOT", "")
    if not root:
        raise ImportError("seal_chain gates need the private bridge checkout "
                          "(set ARCAEON_VET_PRIVATE_ROOT); not shipped in arcaeon")
    if root not in _sys.path:
        _sys.path.insert(0, root)
    from bridge.witness import seal_chain as _sc
    return _sc


register_gate(
    "seal_chain.publishable_path_key", "allowlist",
    lambda: (lambda s: _seal_chain()._is_path(s)),
    "bridge/witness/seal_chain.py _is_path (_PATHKEY + _CHAIN_KEY_SHAPES): what "
    "may appear in a chain row's `file` field and therefore in the PUBLIC chain "
    "export. Widened 2026-09-13 to admit exactly two machine-generated key "
    "shapes, `@liveness/check:<iso>[:retraction]` and `rebreak:<id>:<iso>`, which "
    "had made all 278 rows unexportable. Widening it further would let a value "
    "that is not a digest/timestamp/path/bounded scalar -- i.e. something that "
    "can carry CONTENT -- out of the house in a published export.")

register_gate(
    "seal_chain.publishable_event", "allowlist",
    lambda: (lambda s: _seal_chain()._is_event(s)),
    "bridge/witness/seal_chain.py _EVENTS via _is_event: the closed vocabulary "
    "of a chain row's `event`. 'checked' was added 2026-09-13 in the same commit "
    "and for the same reason (33 rows, including 11 with clean keys, were "
    "unexportable without it). Widening this enum past the values the three real "
    "writers emit is how a free-text field would enter the export wearing an "
    "enum's name.")


# --- CLI -----------------------------------------------------------------------

_EXIT_BY_STATUS = {STATUS_OK: 0, STATUS_DRIFT: 1, STATUS_NO_BASELINE: 2, STATUS_NO_COVERAGE: 2}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m arcaeon.prove.vet.gate_drift",
        description="Differential accept-set check for pattern gates (task 073).")
    parser.add_argument("gate", nargs="?", help="check only this gate; default is every registered gate")
    parser.add_argument("--list", action="store_true", help="list registered gates and exit")
    parser.add_argument("--update-baseline", action="store_true",
                         help="OVERWRITE the baseline from the current corpus + current code. "
                              "Commit the resulting diff as the declaration of an intentional change.")
    args = parser.parse_args(argv)

    if args.list:
        for name in sorted(GATES):
            g = GATES[name]
            print(f"{name}  [{g.kind}]\n    {g.note}")
        return 0

    names = [args.gate] if args.gate else sorted(GATES)
    unknown = [n for n in names if n not in GATES]
    if unknown:
        print(f"unknown gate(s): {unknown} (known: {sorted(GATES)})")
        return 2

    worst = 0
    for name in names:
        if args.update_baseline:
            report = update_baseline_from_corpus(name)
        else:
            report = check_gate(name)
        print(f"[{report.status.upper():^11}] {name}: {report.message}")
        worst = max(worst, _EXIT_BY_STATUS.get(report.status, 2))
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
