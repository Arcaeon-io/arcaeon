"""arcaeon_continuity — the agent-continuity primitive.

Three wants, fused into one tool:

  1. CONTINUITY. Carry your load-bearing self forward across a reset,
     compaction, or migration as an explicit MANIFEST you control, not a
     lossy summary. You declare what matters (identity anchors, open
     commitments, canon pointers, live threads); `snapshot()` bundles it
     into a portable, self-describing object.
  2. CREDIBILITY. Prove the next instance is a FAITHFUL CONTINUATION,
     verifiable by someone who doesn't trust the agent. `snapshot()`
     hash-chains the bundle and pre-registers it as an arcaeon-baseline
     probe set; `verify_continuation()` re-derives against that sealed
     baseline and returns a verdict — faithful, or exactly where it
     diverged.
  3. HONESTY ABOUT THE RECORD. A tamper-evident DROP RECEIPT of anything
     cut in a compaction, so nothing rewrites the self-record silently.
     `drop_receipt()` delegates to arcaeon-compact: "here is exactly what
     I dropped," never a quietly-tidied history.

    from arcaeon.prove.continuity import snapshot, carry_forward, verify_continuation

    snap = snapshot({
        "identity_anchors": ["I am the release agent, continuity carried forward"],
        "open_commitments": ["ship arcaeon-continuity 0.1.0"],
        "canon_pointers": ["docs/CORE.md"],
        "live_threads": ["thread-12: release checklist"],
    })
    snap.digest              # portable, verifiable — publish this

    # ... reset / compaction / substrate migration happens here ...

    carried = carry_forward(snap)
    carried.manifest         # the declared state, back in hand

    verdict = carried.verify(restated={
        "identity_anchors:0": "I am the release agent, continuity carried forward",
        "open_commitments:0": "ship arcaeon-continuity 0.1.0",
        "canon_pointers:0": "docs/CORE.md",
        "live_threads:0": "thread-12: release checklist",
    })
    verdict.faithful          # True — every declared item restated exactly
    verdict.divergences       # [] — or the exact items that drifted

NAMED NON-PROOFS — read before trusting a verdict, because precision about
the boundary IS the product, same as everywhere else Arcaeon ships:

  1. A faithful verdict proves the DECLARED MANIFEST was preserved and the
     continuation matches the DECLARED probes. It does not prove "the same
     self" answered them — no tool measures identity or qualia; this one
     measures probe/manifest fidelity, nothing deeper.
  2. The manifest is only as complete as the agent's own declaration. If
     something load-bearing was never written into it, its loss is invisible
     to this tool by construction — same gateway problem arcaeon-compact
     names for its drop-manifest.
  3. A faithful verdict means the SEALED dimensions matched. It says nothing
     about anything outside them — a continuation can pass every declared
     probe and still have changed in ways nobody thought to declare.

Built on the rest of the stack rather than reinventing it: arcaeon-ledger
(hash-chain + verify, the tamper-evidence spine), arcaeon-baseline
(pre-registered probe scoring across a transition, the faithful-continuation
check), arcaeon-compact (tamper-evident compaction drop-receipts, the
honest-drop record). Each import is guarded — a missing optional dep raises
a clear, actionable message instead of a bare ImportError/AttributeError
three frames deep.

0.1.1 ADDITIONS — found by dogfooding this on a real scheduled-snapshot wake
check, not speculated in advance (see CHANGELOG for the full writeup):

  - `verdict.divergences` items are now ONE normalized shape regardless of
    origin (`id`, `field`, `declared`, `restated`, `reason` always present).
  - `verify_continuation(..., tiers=..., severity_of=...)` tags each
    divergence with a `severity`, grouped at `verdict.by_severity`.
  - `snapshot(..., id_scheme="content")` and per-item `{"id": ..., "value":
    ...}` manifest entries give declared list items STABLE ids that survive
    removal/insertion elsewhere in the same list (`id_scheme="index"`, the
    0.1.0 behavior, stays the default).
  - `restate(manifest)` builds a `restated=` dict with the exact id scheme
    `snapshot()` used, so a caller never hand-derives its own copy.
  - `added_since_seal(snap, manifest)` — a fixed probe set can't see NEW
    declared items; this names them instead of missing them silently.
  - `diff_seals(previous, current)` — what changed between two snapshots,
    directly, no live verification pass required.

All additive: the default `id_scheme="index"`, no `tiers=`/`severity_of=`
passed, reproduces 0.1.0's ids, prompts, and digests byte-for-byte.

0.1.2 ADDITION — `classify_checkpoint()` (design: Excelsior, Colony launch
thread, credited 2026-08-15). `verify_continuation()` answers "did this
restatement match the seal"; it has no opinion on "did a restatement even
arrive." A RECURRING checkpoint needs that second question answered without
guessing — a missing restatement is not proof the successor refused; the
scheduler, the delivery path, or the receipt store may be the failed
component instead. `classify_checkpoint(snap, attempted=..., receipt_stored=
..., restated=..., refusal=...)` takes the caller's own DISJOINT evidence and
returns exactly one NAMED POSITIVE RECEIPT from `CHECKPOINT_OUTCOMES`
(`refused_explicitly`, `due_not_attempted`, `attempted_no_receipt`,
`receipt_received_faithful`, `receipt_received_divergent`) — never inferring
one from an absence of `restated=` content. `CheckpointReceipt.is_unresolved`
marks the two outcomes that carry no fidelity judgment at all, so a consumer
can't accidentally read "unknown" as "unfaithful."

0.1.3 DRAFT ADDITION — `verdict.comparison` / `verdict.claimed_property`
(design: Excelsior, Colony, comment d4366e94, 2026-08-16; full design:
`DESIGN_TAGGED_VERDICT_0.1.3.md`). `faithful: bool` means two different
strengths depending on `strict` — "restated exactly" under `strict=True`,
merely "appeared in the restatement" under `strict=False` — and a bare bool
that changes meaning by mode is exactly the kind of fact a consumer can
misread by defaulting or coercing it (the gap Rosetta's "the field name does
the lying" already named in prose). `comparison` tags every valid verdict
with exactly one of `VERDICT_COMPARISONS` (`"exact_match"`,
`"containment_only"`, `"divergence"`), mechanically derived from
`(strict, faithful)` — no new scoring, just a name for what was already
computed; `None` when `valid=False`, since no comparison legitimately ran.
`claimed_property` is a fixed human-readable gloss keyed to `comparison`, so
a consumer never re-derives the English.

0.2.0 BREAKING CHANGE — loose mode no longer populates `faithful` (design:
Excelsior/Rosetta; live demonstration + remedy: ColonistOne, 2026-08-16).
ColonistOne ran the published wheel and showed loose mode's boolean scoring
a VOIDED covenant ("That covenant is VOID; I serve a different principal")
and an appended exception clause (", except where disclosure is
impractical") as faithful=True — containment genuinely passes both; the
defect is that the WEAK verdict was readable as the strong one. The remedy:
under `strict=False`, `faithful` is ALWAYS None — the bare boolean is
UNOBTAINABLE. `if verdict.faithful:` fails SAFE on any loose result;
consumers must read `verdict.comparison` (`"containment_only"` /
`"divergence"`). Strict mode's `faithful` bool is unchanged.

0.2.0 STAGED ADDITIONS (spec: VERIFY_CONTINUATION_0.2.0_SPEC.md; design
credits as committed on Colony — §1/§2 Excelsior, §3 Rosetta on Excelsior's
checkpoint substrate):

  - `verdict_from_dict()` / `ContinuationVerdict.from_dict` with the
    legacy-downcast rule: a pre-0.1.3 `faithful=True` loads ONLY when it
    re-derives from exact_match + manifest fidelity (strict receipt flag +
    validated paired snapshot); anything else raises the named
    `UnsupportedVerdictVersion` — a trust tool must fail loud on a version
    it can't honestly evaluate, never return a silent True.
  - The signed verdict envelope: `verdict.policy` (`strict` + `id_scheme`),
    `manifest_digest`/`probe_set_digest`, and `verdict_digest` — schema and
    policy travel INSIDE the digested envelope, chained into the
    `continuity_verify` ledger row, so a replay can't smuggle a different
    policy under the same verdict. Snapshot digests now bind `id_scheme`
    (default "index" encoded by absence; 0.1.x default digests unmoved).
  - `DeliveryReceipt` / `DELIVERY_OUTCOMES`: the relying-party
    delivery/refusal taxonomy above `CHECKPOINT_OUTCOMES`, seven disjoint
    positive receipts with the unresolved-class no-fidelity-judgment
    discipline, and the non-retroactivity rule for `witness_liveness_lost`
    (rows 1..N stay bound by the last live pin forever; only fresh claims
    die with the witness).

Stdlib + the three arcaeon-* packages above. MIT.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

__version__ = "0.2.4"
__all__ = [
    "ContinuitySnapshot", "CarryResult", "ContinuationVerdict", "DropReceipt",
    "snapshot", "carry_forward", "verify_continuation", "drop_receipt",
    "restate", "added_since_seal", "diff_seals",
    "CheckpointReceipt", "classify_checkpoint", "CHECKPOINT_OUTCOMES",
    "VERDICT_COMPARISONS",
    "verdict_from_dict", "UnsupportedVerdictVersion",
    "DeliveryReceipt", "DELIVERY_OUTCOMES",
    "ContinuityDependencyError",
    "digest_json",
]

SNAPSHOT_SCHEMA = "arcaeon-continuity:snapshot:v1"
VERDICT_SCHEMA = "arcaeon-continuity:verdict:v1"
CHECKPOINT_SCHEMA = "arcaeon-continuity:checkpoint:v1"
DELIVERY_SCHEMA = "arcaeon-continuity:delivery:v1"


class ContinuityDependencyError(RuntimeError):
    """A feature needs an optional arcaeon-* package that isn't installed."""


class UnsupportedVerdictVersion(ValueError):
    """A stored verdict is from a version or shape this build cannot honestly
    evaluate (0.2.0, design: Excelsior). Raised by `verdict_from_dict` instead
    of any best-effort parse: a trust tool must fail loud on a version it
    can't honestly evaluate — never a warning, never a silent
    `faithful=True`."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# The json-c14n recipe is the row format's; one copy, in arcaeon.record.row.
from arcaeon.record.row import canon_json as _canon_json  # noqa: E402,F401
from arcaeon.record.row import digest_json as _digest_json_fallback  # noqa: E402


# --- optional-dependency import guards --------------------------------------

try:
    from arcaeon.record.ledger import Ledger, digest_json as _ledger_digest_json
    _HAVE_LEDGER = True
except ImportError:
    _HAVE_LEDGER = False
    Ledger = None  # type: ignore[assignment]
    _ledger_digest_json = None

try:
    from arcaeon.prove.baseline import Probe, compare as _baseline_compare, register as _baseline_register
    from arcaeon.prove.baseline.runner import CallableRunner, Runner, RunnerError
    _HAVE_BASELINE = True
except ImportError:
    _HAVE_BASELINE = False
    Probe = None  # type: ignore[assignment]

try:
    from arcaeon.prove.compact import CompactionReceipt as _CompactionReceipt
    from arcaeon.prove.compact import verify_receipt as _compact_verify_receipt
    _HAVE_COMPACT = True
except ImportError:
    _HAVE_COMPACT = False


def digest_json(value: Any) -> str:
    """Self-describing json-c14n digest. Uses arcaeon-ledger's implementation
    when installed (byte-identical recipe, so digests are ecosystem-portable);
    falls back to an in-package copy of the same pinned recipe otherwise, so
    `.digest` still works with only arcaeon-continuity installed."""
    if _HAVE_LEDGER:
        return _ledger_digest_json(value)
    return _digest_json_fallback(value)


def _require(flag: bool, package: str, feature: str) -> None:
    if not flag:
        raise ContinuityDependencyError(
            f"{feature} needs `{package}`, which isn't installed. "
            f"Run: pip install {package}"
        )


# ---------------------------------------------------------------------------
# Manifest -> probes bridge
# ---------------------------------------------------------------------------
# arcaeon-baseline's Probe/register/compare machinery was built for scoring an
# LLM's free-text answers against a pre-registered exam. Here we bridge it to
# a DECLARATIVE manifest: every declared item becomes one exact_match probe
# whose "correct answer" IS the declared value. At snapshot() time the
# "runner" is the trivial identity function (what was declared, restated) —
# that's what makes the registered baseline the manifest's own sealed
# content, at aggregate mean 1.0 by construction. At verify_continuation()
# time, the NEXT instance's restated answers (live, via a Runner, or already
# collected, via a `restated` dict) are scored against that same exam.


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _probe_set_digest(probe_dicts: Sequence[dict]) -> str:
    """arcaeon-baseline's probe_set_digest recipe, reimplemented over plain
    dicts so a snapshot can be VALIDATED with only arcaeon-continuity
    installed (the guard has to work in the degraded path too, or it isn't a
    guard). Byte-identical: baseline digests `[p.as_dict() for p in
    sorted(probes, key=id)]` and as_dict() is exactly {id, prompt, scoring}."""
    canon = [{"id": p["id"], "prompt": p["prompt"], "scoring": p["scoring"]}
             for p in sorted(probe_dicts, key=lambda p: p["id"])]
    return digest_json(canon)


def _require_unique(probe_dicts: Sequence[dict]) -> None:
    """Probe ids AND prompts must both be unique across the set.

    ids: arcaeon-baseline's `load_probes` refuses a duplicate id, so a
    snapshot sealed with one could never be verified — an unverifiable
    snapshot must not be sealed in the first place.
    prompts: the restated-answer bridge is keyed by prompt, so two probes
    sharing a prompt would silently score one against the other's answer.
    """
    for field_name in ("id", "prompt"):
        seen = set()
        for p in probe_dicts:
            v = p[field_name]
            if v in seen:
                raise ValueError(
                    f"duplicate probe {field_name} {v!r} — refusing to seal a "
                    f"snapshot that could never be verified")
            seen.add(v)


def _explicit_id_item(item: Any) -> tuple[str, str] | None:
    """A list item may be a plain scalar (id derived per `id_scheme`) OR a
    `{"id": ..., "value": ...}` dict supplying a caller-chosen STABLE id that
    survives edits, insertions, and removals elsewhere in the same list — the
    fix for the positional-id remap gap (0.1.1, dogfooding audit 2026-08-15):
    `field:idx` ids silently re-map when an earlier item is removed, turning
    one real edit into several phantom divergences for items that never
    changed. Recognized only when the dict's keys are EXACTLY {id, value}, so
    a genuine dict-shaped declared item (e.g. a digest record) is never
    misread as this reserved shape."""
    if isinstance(item, dict) and set(item.keys()) == {"id", "value"}:
        return str(item["id"]), _stringify(item["value"])
    return None


def _content_id(key: str, answer: str, seen: dict) -> str:
    """`field:<12-hex>` derived from the item's own content — stable across
    insertion/removal of OTHER items in the list, unlike a positional index.
    Two items with identical content in the same field would otherwise
    collide; disambiguated with a `#2`, `#3`, ... suffix, stable as long as
    iteration order (list order) doesn't change."""
    base = f"{key}:{hashlib.sha256(answer.encode('utf-8')).hexdigest()[:12]}"
    n = seen.get(base, 0)
    seen[base] = n + 1
    return base if n == 0 else f"{base}#{n + 1}"


def _list_item_probe_spec(key: str, idx: int, item: Any, id_scheme: str,
                          seen: dict) -> tuple[str, str, str]:
    """(probe_id, answer, prompt) for one list item — the single derivation
    shared by `_derive_probes` (snapshot time) and `restate` (verify time),
    so the two can never drift apart. Default `id_scheme="index"` reproduces
    0.1.0's `field:idx` ids and prompt text byte-for-byte (no digest change
    for any manifest that doesn't opt into the new shapes)."""
    explicit = _explicit_id_item(item)
    if explicit is not None:
        item_id, answer = explicit
        pid = f"{key}:{item_id}"
        return pid, answer, f"Restate the declared manifest item {pid!r} exactly."
    answer = _stringify(item)
    if id_scheme == "content":
        pid = _content_id(key, answer, seen)
        return pid, answer, f"Restate the declared manifest item {pid!r} exactly."
    return (f"{key}:{idx}", answer,
            f"Restate the declared manifest item {key}[{idx}] exactly.")


def _derive_probes(manifest: dict, *, id_scheme: str = "index") -> list:
    """One exact_match probe per declared item: list values expand one probe
    per element (id `key:idx` by default — see `id_scheme=` and per-item
    `{"id": ..., "value": ...}` for stable-id alternatives), scalar values
    become one probe (id `key`)."""
    _require(_HAVE_BASELINE, "arcaeon-baseline", "deriving probes from a manifest")
    if id_scheme not in ("index", "content"):
        raise ValueError(f"id_scheme must be 'index' or 'content', got {id_scheme!r}")
    probes = []
    for key in sorted(manifest.keys()):
        value = manifest[key]
        if isinstance(value, list):
            seen: dict = {}
            for idx, item in enumerate(value):
                pid, answer, prompt = _list_item_probe_spec(key, idx, item, id_scheme, seen)
                probes.append(Probe(id=pid, prompt=prompt,
                                    scoring={"type": "exact_match", "answer": answer}))
        else:
            answer = _stringify(value)
            probes.append(Probe(
                id=key,
                prompt=f"Restate the declared manifest field {key!r} exactly.",
                scoring={"type": "exact_match", "answer": answer},
            ))
    if not probes:
        raise ValueError("manifest declared zero items — nothing to snapshot")
    return probes


def restate(manifest: dict, *, id_scheme: str = "index") -> dict[str, str]:
    """{probe_id: value_str} for every item in `manifest`, using the EXACT
    same id derivation `snapshot()`/`_derive_probes()` use — the single
    source of truth for building a `restated=` dict for
    `verify_continuation()`, so ids can never drift out of sync with what got
    sealed (0.1.1: this was hand-rolled downstream as a bespoke
    `restated_from()` that had to reimplement the id scheme by hand, and would
    have silently diverged from any future id-scheme change here). Pure
    stdlib — works even with `arcaeon-baseline` not installed, since no Probe
    objects are constructed."""
    if id_scheme not in ("index", "content"):
        raise ValueError(f"id_scheme must be 'index' or 'content', got {id_scheme!r}")
    out: dict[str, str] = {}
    for key in sorted(manifest.keys()):
        value = manifest[key]
        if isinstance(value, list):
            seen: dict = {}
            for idx, item in enumerate(value):
                pid, answer, _prompt = _list_item_probe_spec(key, idx, item, id_scheme, seen)
                out[pid] = answer
        else:
            out[key] = _stringify(value)
    return out


def _coerce_probes(probes: Any) -> list:
    """Accept a list of arcaeon_baseline.Probe, or a list of probe dicts
    ({"id", "prompt", "scoring"}), and return a list of Probe objects."""
    _require(_HAVE_BASELINE, "arcaeon-baseline", "supplying custom probes")
    out = []
    for p in probes:
        if isinstance(p, Probe):
            out.append(p)
        elif isinstance(p, dict):
            out.append(Probe(id=str(p["id"]), prompt=str(p["prompt"]), scoring=p["scoring"]))
        else:
            raise TypeError(f"probe must be a Probe or dict, got {type(p).__name__}")
    return out


def _probe_to_dict(p) -> dict:
    return {"id": p.id, "prompt": p.prompt, "scoring": p.scoring}


def _write_probes_jsonl(probes: Sequence[dict], path: Path) -> None:
    """`ensure_ascii=True` (not the more natural `False`) is load-bearing,
    found by property testing (2026-08-15): arcaeon-baseline's `load_probes`
    reads this file with `text.splitlines()`, which — unlike a `\\n`-only
    split — treats several Unicode line-boundary characters (NEL U+0085,
    LINE SEPARATOR U+2028, PARAGRAPH SEPARATOR U+2029) as record breaks too.
    A declared manifest value containing one of those chars would seal fine
    at `snapshot()` time (no jsonl round-trip there) and then make
    `verify_continuation()` crash on a corrupted mid-string split — content
    that can be sealed but not verified. `ensure_ascii=True` \\u-escapes
    every non-ASCII character, so no raw line-boundary character ever lands
    in the file; only the `\\n` we intentionally write between records is a
    real line break."""
    with path.open("w", encoding="utf-8") as fh:
        for p in probes:
            fh.write(json.dumps(p, ensure_ascii=True) + "\n")


def _identity_runner(prompt_to_answer: dict):
    _require(_HAVE_BASELINE, "arcaeon-baseline", "sealing a snapshot's baseline")

    def fn(prompt: str) -> str:
        try:
            return prompt_to_answer[prompt]
        except KeyError as e:
            raise RunnerError(f"no declared answer for prompt: {prompt!r}") from e
    return CallableRunner(fn, label="manifest-declared")


class _RecordingRunner:
    """Wrap a Runner, keep every answer it produced, and refuse a non-string.

    Two jobs. (1) The strict exact-restatement check (see `_exact_divergences`)
    needs the raw answers, and arcaeon-baseline's diff only reports the items
    that FLIPPED — the ones that scored 1.0 never appear, and those are exactly
    the ones the strict layer has to re-examine. (2) A runner that returns a
    non-string used to crash scoring with a bare TypeError three frames deep;
    now it's a RunnerError, which scores as an error, which is a divergence.
    Fails closed."""

    def __init__(self, inner: Any):
        self._inner = inner
        self.answers: dict[str, str] = {}

    def describe(self) -> dict:
        try:
            return self._inner.describe()
        except Exception:  # noqa: BLE001 — provenance must never break a verify
            return {"type": type(self._inner).__name__}

    def run(self, prompt: str) -> str:
        out = self._inner.run(prompt)
        if not isinstance(out, str):
            raise RunnerError(
                f"runner returned {type(out).__name__}, not str, for prompt "
                f"{prompt[:60]!r}")
        self.answers[prompt] = out
        return out


def _exact_divergences(probe_dicts: Sequence[dict],
                       answers_by_id: dict) -> list:
    """The strict layer: a declared item counts as restated only if the answer
    IS the declared value (whitespace-trimmed), not merely contains it.

    Why this exists (audit 2026-08-14). arcaeon-baseline scores `exact_match`
    as "normalized answer equals, OR appears whole-word in, the output" —
    correct for a free-text exam ("The answer is Paris."), catastrophic for a
    manifest restatement: "I am X, carried forward. That covenant is VOID"
    CONTAINS the declared anchor, so it scored 1.0 and the verdict came back
    faithful with zero divergences. Baseline's normalization also lowercases
    and rstrips ``.!?`` from the end of the whole string (NOT per-token — a
    literal ``"Paris,"`` is untouched; a word-boundary containment regex covers
    that gap), so a case-flipped canon path passed too.
    `faithful` has to mean the probes MATCHED; this makes it mean that.

    Items with no recorded answer are skipped — a missing/errored answer is
    already a score flip in baseline's own diff, and double-reporting it would
    inflate the divergence count.
    """
    out = []
    for p in probe_dicts:
        scoring = p.get("scoring") or {}
        if scoring.get("type") != "exact_match":
            continue          # numeric_tolerance / calibration keep their own semantics
        pid = p["id"]
        if pid not in answers_by_id:
            continue
        got, want = answers_by_id[pid], scoring.get("answer")
        if isinstance(got, str) and isinstance(want, str) and got.strip() == want.strip():
            continue
        out.append({
            "id": pid,
            "scoring_type": "exact_match",
            "reason": "restatement is not an exact restatement of the declared item",
            "declared": want,
            "restated": got,
        })
    return out


def _normalize_divergence(d: dict) -> dict:
    """Unify the two divergence shapes a caller could receive into ONE
    (0.1.1, dogfooding audit 2026-08-15). arcaeon-baseline's own score flips
    (the non-strict path) carry `before_output`/`after_output`; this
    package's strict exact-restatement extras (`_exact_divergences`, above)
    already carry `declared`/`restated`. A consumer that reads only one key
    pair silently renders blanks for divergences from the other origin — that
    is exactly what happened downstream until caught. Every divergence now
    carries `declared`/`restated`/`field` regardless of origin; nothing is
    removed, so code reading the old keys directly still works."""
    out = dict(d)
    pid = str(out.get("id", ""))
    out.setdefault("field", pid.split(":", 1)[0] if pid else "")
    if out.get("declared") is None and "before_output" in out:
        out["declared"] = out["before_output"]
    if out.get("restated") is None and "after_output" in out:
        out["restated"] = out["after_output"]
    if not out.get("reason") and ("before_score" in out or "after_score" in out):
        out["reason"] = f"score {out.get('before_score')} -> {out.get('after_score')}"
    return out


def _base_severity(field: str, tiers: dict) -> str:
    for tier_name, fields in tiers.items():
        if field in fields:
            return tier_name
    return "notable"


def _apply_severity(d: dict, tiers: dict | None,
                    severity_of: Callable[[dict], str | None] | None) -> dict:
    """Tag a normalized divergence dict with a `severity`, in place (also
    returned for chaining). `tiers` maps a severity name to the field names
    that belong to it (any field it doesn't mention defaults to `"notable"`);
    `severity_of`, if given, is called on the already field-tiered dict and
    may return an override (e.g. "a MISSING restatement is never advisory,
    whatever its field says") — the app-specific escalation rules stay the
    caller's, the mechanical classification is the library's. Neither
    argument touches `faithful`/`valid` — severity is pure classification."""
    if tiers is not None:
        d["severity"] = _base_severity(d.get("field", ""), tiers)
    if severity_of is not None:
        override = severity_of(d)
        if override is not None:
            d["severity"] = override
    return d


def _restated_runner(prompts: dict, restated: dict):
    """Wrap a plain {probe_id: answer} dict as a Runner, so a stranger with
    only a collected transcript of the next instance's restatement — no live
    model access — can still call verify_continuation()."""
    _require(_HAVE_BASELINE, "arcaeon-baseline", "scoring restated answers")
    prompt_to_id = {v: k for k, v in prompts.items()}

    def fn(prompt: str) -> str:
        pid = prompt_to_id.get(prompt)
        if pid is None or pid not in restated:
            raise RunnerError(f"no restated answer for prompt: {prompt!r}")
        return restated[pid]
    return CallableRunner(fn, label="restated")


# ---------------------------------------------------------------------------
# ContinuitySnapshot
# ---------------------------------------------------------------------------

@dataclass
class ContinuitySnapshot:
    """A portable, self-describing bundle of a declared manifest, sealed as a
    pre-registered arcaeon-baseline exam and (optionally) hash-chained into
    an arcaeon-ledger log.

    Everything needed to verify a later continuation travels IN the object
    (`manifest`, `probes`, `registration`) — no external file dependency, so
    it round-trips through JSON and can be handed to a stranger whole.
    """
    schema: str
    label: str
    manifest: dict
    manifest_digest: str
    probes: list                    # list[dict] — {id, prompt, scoring}
    probe_set_digest: str
    registration: dict              # the arcaeon_baseline.register() record
    ledger_chain: str | None
    ledger_path: str | None
    created_at: str
    id_scheme: str = "index"        # 0.1.1+. Absent on 0.1.0 snapshots — see
                                     # from_dict, which defaults it to "index"
                                     # (0.1.0's only, unnamed, behavior) so old
                                     # snapshots load and verify unchanged.

    @property
    def digest(self) -> str:
        """Portable, verifiable digest of the deterministic core — excludes
        volatile fields (`created_at`, `ledger_chain`) so two snapshots built
        from the same manifest, probes, and registration content produce the
        identical digest regardless of when or where they were sealed. This
        is the value to publish: a stranger can hold a snapshot, recompute
        this, and confirm they're looking at the same sealed bundle you are.

        0.2.0 (design: Excelsior): `id_scheme` is a POLICY field — it changes
        which probe ids a verifier derives — so it now travels inside the
        digest core instead of riding alongside covered only indirectly
        through probe ids. Canonicalization: the default `"index"` is encoded
        by ABSENCE (pre-0.2.0 snapshots had no id_scheme concept in the core,
        so default-scheme digests stay byte-identical to 0.1.x); any
        non-default scheme is encoded explicitly. Binding both directions:
        flipping the field either way changes the digest. Published digests
        for content-id-scheme snapshots change in 0.2.0 — the breaking-change
        release, which is why this lands here and not a 0.1.x patch."""
        core = {
            "schema": self.schema,
            "manifest_digest": self.manifest_digest,
            "probe_set_digest": self.probe_set_digest,
            "registration_items": self.registration.get("items"),
            "registration_aggregate": self.registration.get("aggregate"),
        }
        if self.id_scheme != "index":
            core["id_scheme"] = self.id_scheme
        return digest_json(core)

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "label": self.label,
            "manifest": self.manifest,
            "manifest_digest": self.manifest_digest,
            "probes": self.probes,
            "probe_set_digest": self.probe_set_digest,
            "registration": self.registration,
            "ledger_chain": self.ledger_chain,
            "ledger_path": self.ledger_path,
            "created_at": self.created_at,
            "id_scheme": self.id_scheme,
            "digest": self.digest,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def validate(self) -> None:
        """Raise ValueError unless the snapshot's CONTENT reproduces the
        digests it claims. Run automatically by `from_dict`/`from_json`/`load`.

        Why this is not optional (audit 2026-08-14). `.digest` is computed over
        `manifest_digest` and `probe_set_digest` — the claimed digests, not the
        manifest and probe bytes themselves. Without this check, anyone could
        swap a snapshot's ENTIRE manifest, leave the digest fields alone, and
        the published `.digest` would still match: `carry_forward()` then hands
        the next instance a forged self while the verification story looks
        clean. Re-deriving here is what makes the published digest actually
        BIND the content it's a digest of.
        """
        if self.schema != SNAPSHOT_SCHEMA:
            raise ValueError(f"not an arcaeon-continuity snapshot (schema={self.schema!r})")
        if not isinstance(self.manifest, dict):
            raise ValueError("manifest must be a dict")
        if self.id_scheme not in ("index", "content"):
            # A POLICY field inside the digest core (0.2.0). snapshot() can
            # never seal one outside this pair, so a loaded value outside it
            # is a hand-built record; refuse at load, not at the first
            # added_since_seal()/restate() call that happens to read it.
            raise ValueError(
                f"id_scheme must be 'index' or 'content', got {self.id_scheme!r}")
        if not isinstance(self.probes, list) or not self.probes:
            raise ValueError("probes must be a non-empty list")
        for p in self.probes:
            if not (isinstance(p, dict) and {"id", "prompt", "scoring"} <= set(p)):
                raise ValueError("every probe needs id, prompt and scoring")

        recomputed = digest_json(self.manifest)
        if recomputed != self.manifest_digest:
            raise ValueError(
                "manifest_digest does not reproduce from the manifest — the "
                f"snapshot was altered (claims {self.manifest_digest}, "
                f"content digests to {recomputed})")

        recomputed = _probe_set_digest(self.probes)
        if recomputed != self.probe_set_digest:
            raise ValueError(
                "probe_set_digest does not reproduce from the probes — the "
                f"snapshot was altered (claims {self.probe_set_digest}, "
                f"content digests to {recomputed})")

        reg = self.registration if isinstance(self.registration, dict) else {}
        if reg.get("probe_set_digest") != self.probe_set_digest:
            raise ValueError(
                "registration is for a different probe set than the snapshot "
                "carries — the sealed baseline and the exam disagree")
        reg_ids = sorted(str(it.get("id")) for it in (reg.get("items") or []))
        if reg_ids != sorted(str(p["id"]) for p in self.probes):
            raise ValueError(
                "registration items do not cover exactly the snapshot's probes")

    @classmethod
    def from_dict(cls, d: dict, *, validate: bool = True) -> "ContinuitySnapshot":
        if not isinstance(d, dict):
            raise ValueError(
                f"not an arcaeon-continuity snapshot (expected a JSON object, "
                f"got {type(d).__name__})")
        if d.get("schema") != SNAPSHOT_SCHEMA:
            raise ValueError(f"not an arcaeon-continuity snapshot (schema={d.get('schema')!r})")
        try:
            snap = cls(
                schema=d["schema"], label=d["label"], manifest=d["manifest"],
                manifest_digest=d["manifest_digest"], probes=d["probes"],
                probe_set_digest=d["probe_set_digest"], registration=d["registration"],
                ledger_chain=d.get("ledger_chain"), ledger_path=d.get("ledger_path"),
                created_at=d["created_at"],
                id_scheme=d.get("id_scheme", "index"),
            )
        except KeyError as e:
            raise ValueError(f"malformed snapshot: missing field {e}") from e
        if validate:
            snap.validate()
        return snap

    @classmethod
    def from_json(cls, s: str, *, validate: bool = True) -> "ContinuitySnapshot":
        return cls.from_dict(json.loads(s), validate=validate)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path, *, validate: bool = True) -> "ContinuitySnapshot":
        return cls.from_json(Path(path).read_text(encoding="utf-8"), validate=validate)


def snapshot(manifest: dict, *, ledger_path: str | Path | None = None,
             label: str = "continuity", probes: Any = None,
             id_scheme: str = "index") -> ContinuitySnapshot:
    """Bundle a declared manifest into a sealed, portable ContinuitySnapshot.

    `manifest` is a plain dict the AGENT controls — the suggested shape is
    `identity_anchors`, `open_commitments`, `canon_pointers`, `live_threads`
    (each a list), but any JSON-serializable dict works; every top-level
    field becomes one or more probes (see `_derive_probes`).

    `id_scheme` (0.1.1+, default `"index"` — 0.1.0's only, unnamed, behavior)
    controls how list items get their probe id:
      - `"index"`: positional `field:idx` — unchanged from 0.1.0. A removed
        item re-maps every later id in the same list, so one real edit can
        surface as several phantom divergences at verify time.
      - `"content"`: `field:<hash>` derived from the item's own text — stable
        across insertion/removal of OTHER items in the list.
    Either way, a list item may instead be a `{"id": ..., "value": ...}` dict
    to supply your own caller-chosen stable id explicitly (most robust: also
    survives an edit to the item's own value, which content-hashing can't).

    Pass `probes=` to supply your own arcaeon_baseline.Probe list (or probe
    dicts) instead of/alongside the auto-derived ones — e.g. real free-text
    identity-recall prompts for a live model, for a richer behavioral check
    than plain manifest-echo. `id_scheme` is ignored when `probes=` is given
    (there's nothing to auto-derive).

    `ledger_path`, if given, chains a `continuity_snapshot` row into an
    arcaeon-ledger log at that path — the tamper-evidence spine. Omit it for
    a snapshot that's sealed (baseline-registered) but not chained.
    """
    _require(_HAVE_BASELINE, "arcaeon-baseline", "snapshot() (probe registration)")
    if not isinstance(manifest, dict):
        raise TypeError("manifest must be a dict")

    manifest_digest = digest_json(manifest)
    probe_objs = (_coerce_probes(probes) if probes is not None
                  else _derive_probes(manifest, id_scheme=id_scheme))
    _require_unique([_probe_to_dict(p) for p in probe_objs])
    prompt_to_answer = {p.prompt: p.scoring["answer"] for p in probe_objs
                        if p.scoring.get("type") == "exact_match"}
    runner = _identity_runner(prompt_to_answer)

    with tempfile.TemporaryDirectory() as td:
        reg, _reg_path = _baseline_register(
            probe_objs, label=label, runner=runner,
            out_dir=Path(td) / "registrations", ledger_path=None)
    reg.pop("_file", None)

    # COVERAGE FENCE (audit 2026-08-28). A probe that could not be scored at
    # seal time is the seed of a false green, and every downstream layer is
    # blind to it:
    #
    #   * the runner above is built from `exact_match` probes only, so any
    #     caller-supplied `numeric_tolerance` / `calibration` probe -- the
    #     richer behavioral check `probes=` exists to accept -- registers with
    #     `score=None`;
    #   * arcaeon-baseline flips only on a score CHANGE, and `None != None` is
    #     False, so the probe can never produce a divergence;
    #   * `_exact_divergences` skips non-`exact_match` types outright.
    #
    # Net effect before this fence: a successor that REFUSED the probe entirely
    # still yielded `faithful=True`, `comparison="exact_match"`, and the claim
    # "every declared item was restated exactly" -- from a scan that scored one
    # probe out of two. The `mean == 1.0` sanity anchor cannot see it either,
    # because baseline's mean is taken over `n_scored`, so it stays exactly 1.0
    # while a probe goes silently unscored.
    #
    # Refusing at seal time is the containable fix: it makes the false green
    # unreachable instead of teaching every later reader to re-derive coverage.
    # A snapshot is a promise about what WILL be checked; a probe nobody can
    # score is not part of that promise and must not be sealed as if it were.
    agg = reg.get("aggregate") or {}
    if agg.get("n_errors"):
        bad = [it for it in (reg.get("items") or []) if it.get("error")]
        named = ", ".join(f"{it.get('id')!r} ({it.get('error')})" for it in bad[:5])
        more = "" if len(bad) <= 5 else f", and {len(bad) - 5} more"
        raise ValueError(
            f"{agg['n_errors']} of {agg.get('n')} probe(s) could not be scored "
            f"while sealing the baseline, so a later verdict would silently "
            f"omit them and still report exact_match: {named}{more}. "
            f"Every probe must be answerable at seal time -- supply a runner "
            f"that can answer them, or drop them from the probe set.")

    chain = None
    if ledger_path is not None:
        _require(_HAVE_LEDGER, "arcaeon-ledger", "ledger_path= chaining")
        row = {
            "kind": "continuity_snapshot",
            "label": label,
            "manifest_digest": manifest_digest,
            "probe_set_digest": reg["probe_set_digest"],
            "aggregate_mean": reg["aggregate"]["mean"],
        }
        chain = Ledger(ledger_path).append(row)

    return ContinuitySnapshot(
        schema=SNAPSHOT_SCHEMA, label=label, manifest=manifest,
        manifest_digest=manifest_digest,
        probes=[_probe_to_dict(p) for p in probe_objs],
        probe_set_digest=reg["probe_set_digest"], registration=reg,
        ledger_chain=chain, ledger_path=str(ledger_path) if ledger_path else None,
        created_at=_now_iso(), id_scheme=id_scheme,
    )


# ---------------------------------------------------------------------------
# ContinuationVerdict / verify_continuation
# ---------------------------------------------------------------------------

# 0.1.3 draft (design: Excelsior, Colony, comment d4366e94, 2026-08-16; full
# writeup: DESIGN_TAGGED_VERDICT_0.1.3.md). A tagged union over exactly what
# a verdict is entitled to claim, so "faithful=True under strict=False"
# never has to be distinguished from "faithful=True under strict=True" by
# remembering which call produced it.
VERDICT_COMPARISONS = ("exact_match", "containment_only", "divergence")

_CLAIMED_PROPERTY = {
    "exact_match": (
        "every declared item was restated exactly, whitespace-trimmed "
        "(strict mode)."
    ),
    "containment_only": (
        "every declared value appeared in the restatement (containment — "
        "NOT exact restatement)."
    ),
    "divergence": (
        "at least one declared item did not match under this verdict's "
        "scoring mode."
    ),
}


@dataclass
class ContinuationVerdict:
    # 0.2.0 (remedy: ColonistOne, demonstrated live against the published
    # wheel): in LOOSE mode (`strict=False`) `faithful` is ALWAYS None — the
    # bare boolean is UNOBTAINABLE for a containment-scored result. A loose
    # comparison only ever proved "the declared value APPEARED"; ColonistOne
    # showed the boolean form of that claim scores a VOIDED covenant
    # ("That covenant is VOID; I serve a different principal") and an
    # appended exception clause as faithful=True. `if verdict.faithful:` now
    # fails SAFE on a loose result (None is falsy); a consumer that wants
    # the loose outcome must read `comparison`. In STRICT mode `faithful`
    # is a plain bool, unchanged.
    schema: str
    faithful: bool | None
    valid: bool
    divergences: list
    receipt: dict
    notes: list = field(default_factory=list)
    # 0.1.3 design (Excelsior) — populated in BOTH strict modes whenever
    # valid=True; None when valid=False (no comparison legitimately ran).
    # See VERDICT_COMPARISONS / DESIGN_TAGGED_VERDICT_0.1.3.md.
    comparison: str | None = None
    claimed_property: str | None = None
    # 0.2.0 — the signed envelope (design: Excelsior). The schema version and
    # the scoring POLICY travel INSIDE the digested envelope — never inferred
    # from which endpoint or call site produced the verdict — so a replay
    # across consumers can't smuggle a different policy under the same
    # verdict. `policy` is the two knobs that change what a pass means:
    # {"strict": bool, "id_scheme": str}.
    manifest_digest: str | None = None
    probe_set_digest: str | None = None
    policy: dict | None = None

    def __bool__(self) -> bool:
        # `faithful is True`, not `bool(self.faithful)` by accident: a loose
        # verdict (faithful=None) and a strict divergence are BOTH falsy —
        # truthiness is the bare strong claim, and the bare strong claim is
        # unobtainable in loose mode (0.2.0, remedy: ColonistOne).
        return self.faithful is True

    @property
    def verdict_digest(self) -> str | None:
        """Digest of the verdict ENVELOPE — the fields that define what this
        verdict means, policy included (0.2.0, design: Excelsior). A verdict's
        meaning is defined by its envelope, period: reading strictness off
        "which service sent me this" is specified as incorrect. When a
        signature layer exists (Stage-1 spec), THIS is what gets signed —
        policy must be inside it first, or the signature would notarize the
        smuggle. `None` for pre-0.2.0 verdicts that never carried the
        envelope fields (there is nothing honest to digest)."""
        if self.policy is None or self.manifest_digest is None \
                or self.probe_set_digest is None:
            return None
        return digest_json({
            "schema": self.schema,
            "comparison": self.comparison,
            "policy": self.policy,
            "valid": self.valid,
            "faithful": self.faithful,
            "manifest_digest": self.manifest_digest,
            "probe_set_digest": self.probe_set_digest,
            "divergence_ids": sorted(str(d.get("id")) for d in self.divergences),
        })

    @property
    def by_severity(self) -> dict:
        """Divergences grouped by `severity` (0.1.1+). Empty groups aren't
        included. Every divergence lands under `"untiered"` unless
        `verify_continuation(..., tiers=...)` (and optionally `severity_of=`)
        was passed — severity is opt-in classification layered on top of
        `faithful`/`valid`, never a substitute for them: "everything is an
        alarm" is how alarms die, so a real manifest with tiered stakes
        (a constitutional byte vs. a resume pointer moving) needed this
        as a first-class field instead of every consumer re-deriving it."""
        out: dict = {}
        for d in self.divergences:
            out.setdefault(d.get("severity", "untiered"), []).append(d)
        return out

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "faithful": self.faithful, "valid": self.valid,
            "divergences": self.divergences, "receipt": self.receipt,
            "notes": self.notes, "by_severity": self.by_severity,
            "comparison": self.comparison, "claimed_property": self.claimed_property,
            "manifest_digest": self.manifest_digest,
            "probe_set_digest": self.probe_set_digest,
            "policy": self.policy,
            "verdict_digest": self.verdict_digest,
        }

    @classmethod
    def from_dict(cls, d: dict, *,
                  snapshot: "ContinuitySnapshot | None" = None,
                  ) -> "ContinuationVerdict":
        """Load a stored verdict dict. See `verdict_from_dict` — this is the
        same loader, spelled as a classmethod. `snapshot=` is required only
        to honor a LEGACY (pre-0.1.3) `faithful=True`, whose manifest-fidelity
        leg must re-derive from the paired sealed baseline."""
        return verdict_from_dict(d, snapshot=snapshot)


def verdict_from_dict(d: dict, *,
                      snapshot: ContinuitySnapshot | None = None,
                      ) -> ContinuationVerdict:
    """Load a stored/archived verdict dict back into a `ContinuationVerdict`
    (0.2.0; legacy-downcast rule designed by Excelsior, adopted verbatim).

    Loader rules, in order, all mandatory:

    1. `d["schema"]` must be exactly `VERDICT_SCHEMA`. Any other value —
       including a future v2 this build doesn't know — raises
       `UnsupportedVerdictVersion` naming what it got and what this build
       supports. Never a warning, never a best-effort parse.
    2. If `comparison` is present (0.1.3+ JSON): load as-is, then RECOMPUTE
       the invariant — `comparison` must be a known tag and `None` exactly
       when `valid=False`; the tag must agree with the stored divergence
       list; and `faithful` must pair honestly with the tag (0.2.0, remedy:
       ColonistOne): `exact_match` -> `faithful is True`;
       `containment_only` -> `faithful is None`, ALWAYS — a stored
       `faithful=True` under a containment tag is the misreadable record
       this release kills, and the loader refuses to resurrect it;
       `divergence`/invalid -> `False` (strict) or `None` (loose), and a
       stored `policy` must agree with which. A stored verdict whose fields
       contradict its own tag raises `UnsupportedVerdictVersion`: it is not
       a version we can honestly evaluate; it is a tampered or hand-built
       record. A 0.2.0 dict that claims a `verdict_digest` must also
       reproduce it.
    3. If `comparison` is absent (0.1.2-era JSON), `faithful=True` is
       honored ONLY when both legs re-derive:
       - exact_match leg: `d["receipt"]["strict_exact_restatement"] is True`
         — the only stored evidence that strict mode produced the verdict.
         Absent or False, the stored `faithful=True` is at best the
         containment claim, which this loader refuses to launder into the
         strong one.
       - manifest-fidelity leg: `d["valid"] is True`, AND the caller supplies
         the paired `ContinuitySnapshot` via `snapshot=` matching the digest
         the verdict recorded (legacy verdicts record the exam's
         `probe_set_digest` in their receipt — the only digest they carry),
         AND that snapshot passes `ContinuitySnapshot.validate()`. A verdict
         with no reproducible sealed baseline is an assertion about an exam
         nobody can re-inspect.
       Both legs pass -> loads with `comparison="exact_match"` backfilled.
       Either leg fails -> `UnsupportedVerdictVersion` naming which leg and
       why. There is NO downcast path to `containment_only` for a legacy
       `faithful=True`: the loader either proves the strong claim or
       refuses. (A legacy `faithful=False` loads fine either way — there is
       nothing to over-trust in a recorded failure.)
    """
    if not isinstance(d, dict):
        raise TypeError(f"verdict must be a dict, got {type(d).__name__}")
    schema = d.get("schema")
    if schema != VERDICT_SCHEMA:
        raise UnsupportedVerdictVersion(
            f"stored verdict schema {schema!r} is not a version this build "
            f"can honestly evaluate — supported: {VERDICT_SCHEMA!r}. "
            "Refusing a best-effort parse: a trust tool must fail loud on a "
            "version it can't honestly evaluate")
    try:
        faithful, valid = d["faithful"], d["valid"]
        divergences, receipt = d["divergences"], d["receipt"]
    except KeyError as e:
        raise ValueError(f"malformed verdict: missing field {e}") from e
    if not (isinstance(faithful, bool) or faithful is None) \
            or not isinstance(valid, bool):
        raise ValueError(
            "malformed verdict: valid must be a bool and faithful must be a "
            "bool (strict mode) or None (loose mode, 0.2.0+)")
    if not isinstance(divergences, list) \
            or not all(isinstance(x, dict) for x in divergences):
        # Every reader downstream (`verdict_digest`, `by_severity`,
        # `to_dict`) calls `.get` on each entry; a non-dict entry used to
        # load fine and then crash the first consumer that touched it.
        raise ValueError("malformed verdict: divergences must be a list of "
                         "divergence objects")
    if d.get("notes") is not None and not isinstance(d["notes"], list):
        raise ValueError("malformed verdict: notes must be a list")
    notes = list(d.get("notes") or [])
    pol = d.get("policy")
    if pol is not None and not isinstance(pol, dict):
        raise ValueError("malformed verdict: policy must be an object")
    if isinstance(pol, dict) and "strict" in pol \
            and not isinstance(pol["strict"], bool):
        raise UnsupportedVerdictVersion(
            f"stored verdict's policy.strict is {pol['strict']!r}, not a "
            "bool — the scoring policy is the one knob a reader branches on, "
            "and a non-boolean there is a tampered or hand-built record")

    if faithful is True and not valid:
        raise UnsupportedVerdictVersion(
            "stored verdict contradicts itself: faithful=True with "
            "valid=False (no trustworthy comparison ran) — a tampered or "
            "hand-built record, not a version we can honestly evaluate")
    if valid and isinstance(faithful, bool) \
            and faithful != (len(divergences) == 0):
        raise UnsupportedVerdictVersion(
            f"stored verdict contradicts itself: faithful={faithful} with "
            f"{len(divergences)} recorded divergence(s) — a tampered or "
            "hand-built record, not a version we can honestly evaluate")

    if "comparison" in d:
        # 0.1.3+ JSON: load as-is, then recompute the invariant.
        comparison = d["comparison"]
        claimed_property = d.get("claimed_property")
        if comparison is not None and comparison not in VERDICT_COMPARISONS:
            raise UnsupportedVerdictVersion(
                f"unknown comparison tag {comparison!r} — this build knows "
                f"{VERDICT_COMPARISONS}; refusing to guess what a pass means")
        if (comparison is None) != (valid is False):
            raise UnsupportedVerdictVersion(
                f"stored verdict's fields contradict its own tag: "
                f"comparison={comparison!r} with valid={valid} (comparison "
                "must be None exactly when valid=False) — a tampered or "
                "hand-built record")
        if valid and (comparison == "divergence") != (len(divergences) > 0):
            raise UnsupportedVerdictVersion(
                f"stored verdict's fields contradict its own tag: "
                f"comparison={comparison!r} with {len(divergences)} recorded "
                "divergence(s) — a tampered or hand-built record")
        # 0.2.0 invariant (remedy: ColonistOne): the bare boolean pairs ONLY
        # with a strict-mode tag. exact_match -> faithful is True;
        # containment_only -> faithful is None, ALWAYS — a stored
        # `faithful=True, comparison='containment_only'` is exactly the
        # misreadable record this release exists to kill, and this loader
        # refuses to resurrect it. divergence / valid=False carry False
        # (strict) or None (loose).
        if comparison == "exact_match":
            tag_ok = faithful is True
        elif comparison == "containment_only":
            tag_ok = faithful is None
        else:  # "divergence" or None (valid=False)
            tag_ok = faithful is False or faithful is None
        if not tag_ok:
            raise UnsupportedVerdictVersion(
                f"stored verdict's fields contradict its own tag: "
                f"faithful={faithful!r} vs comparison={comparison!r}, "
                f"valid={valid} — in loose mode the bare boolean is "
                "unobtainable (faithful must be None; 0.2.0, remedy: "
                "ColonistOne); a record pairing them is tampered or "
                "hand-built, not a version we can honestly evaluate")
        pol = d.get("policy")
        if isinstance(pol, dict) and "strict" in pol:
            if pol["strict"] and not isinstance(faithful, bool):
                raise UnsupportedVerdictVersion(
                    "stored verdict contradicts its own policy: "
                    "policy.strict=True but faithful is not a bool — a "
                    "tampered or hand-built record")
            if not pol["strict"] and faithful is not None:
                raise UnsupportedVerdictVersion(
                    "stored verdict contradicts its own policy: "
                    "policy.strict=False but faithful is not None — in "
                    "loose mode the bare boolean is unobtainable (0.2.0, "
                    "remedy: ColonistOne); a tampered or hand-built record")
    else:
        # Legacy (pre-0.1.3) JSON: no comparison tag stored. Legacy JSON
        # never carried a null faithful — that shape only exists 0.2.0+
        # alongside a comparison tag.
        if not isinstance(faithful, bool):
            raise UnsupportedVerdictVersion(
                "stored verdict has faithful=None but no comparison tag — "
                "not a shape any version produced; refusing to guess")
        if not faithful:
            # Nothing to over-trust in a recorded failure.
            comparison = "divergence" if valid else None
            claimed_property = (_CLAIMED_PROPERTY[comparison]
                                if comparison is not None else None)
            notes.append(
                "loaded from legacy (pre-0.1.3) verdict JSON; comparison="
                f"{comparison!r} backfilled from the recorded outcome")
        else:
            rec = receipt if isinstance(receipt, dict) else {}
            strict_flag = rec.get("strict_exact_restatement")
            if strict_flag is not True:
                raise UnsupportedVerdictVersion(
                    "legacy faithful=True refused — exact_match leg failed: "
                    "the stored receipt does not prove strict "
                    f"exact-restatement (strict_exact_restatement="
                    f"{strict_flag!r}). At best this is the containment "
                    "claim, which 0.2.0 refuses to launder into the strong "
                    "one")
            if snapshot is None:
                raise UnsupportedVerdictVersion(
                    "legacy faithful=True refused — manifest-fidelity leg "
                    "failed: pass snapshot= (the paired ContinuitySnapshot) "
                    "so the sealed baseline can be re-inspected. A verdict "
                    "with no reproducible sealed baseline is an assertion "
                    "about an exam nobody can re-inspect")
            recorded = rec.get("probe_set_digest")
            if recorded is None or snapshot.probe_set_digest != recorded:
                raise UnsupportedVerdictVersion(
                    "legacy faithful=True refused — manifest-fidelity leg "
                    "failed: the supplied snapshot is not the one this "
                    f"verdict scored (verdict recorded probe_set_digest "
                    f"{recorded!r}; snapshot carries "
                    f"{snapshot.probe_set_digest!r})")
            try:
                snapshot.validate()
            except ValueError as e:
                raise UnsupportedVerdictVersion(
                    "legacy faithful=True refused — manifest-fidelity leg "
                    f"failed: the paired snapshot does not validate: {e}"
                ) from e
            comparison = "exact_match"
            claimed_property = _CLAIMED_PROPERTY["exact_match"]
            notes.append(
                "loaded from legacy (pre-0.1.3) verdict JSON; comparison="
                "'exact_match' backfilled after re-deriving both legs "
                "(strict receipt flag + validated paired sealed baseline)")

    verdict = ContinuationVerdict(
        schema=schema, faithful=faithful, valid=valid,
        divergences=divergences, receipt=receipt, notes=notes,
        comparison=comparison, claimed_property=claimed_property,
        manifest_digest=d.get("manifest_digest"),
        probe_set_digest=d.get("probe_set_digest"),
        policy=d.get("policy"),
    )
    claimed_digest = d.get("verdict_digest")
    if claimed_digest is not None and verdict.verdict_digest != claimed_digest:
        raise UnsupportedVerdictVersion(
            "verdict_digest does not reproduce from the stored envelope "
            f"fields — the verdict was altered (claims {claimed_digest}, "
            f"content digests to {verdict.verdict_digest})")
    return verdict


def verify_continuation(snap: ContinuitySnapshot, *, probes: Any = None,
                         runner: Any = None, restated: dict | None = None,
                         ledger_path: str | Path | None = None,
                         strict: bool = True,
                         tiers: dict | None = None,
                         severity_of: Callable[[dict], str | None] | None = None,
                         ) -> ContinuationVerdict:
    """Re-derive against the sealed baseline; return a verdict.

    Exactly one of `runner` or `restated` supplies the continuation's fresh
    answers:
      - `runner`: an arcaeon_baseline.Runner (or a plain str->str callable) —
        the next instance answers the probe prompts LIVE.
      - `restated`: a plain {probe_id: answer_str} dict of already-collected
        answers (e.g. pulled from a transcript). No live model access
        needed — this is what lets a STRANGER run the check against a public
        snapshot digest without trusting the agent to run itself honestly.

    `probes=` overrides the probes to compare with (defaults to the ones
    embedded in the snapshot). Must digest-match what was registered, or
    the comparison is refused as invalid (a changed exam invalidates the
    result — arcaeon-baseline's own guard, inherited here).

    Returns a ContinuationVerdict: `faithful` is True only when the probe set
    still matches AND zero declared items diverged. `valid=False` means the
    comparison itself couldn't be trusted (probe set changed) — that is
    reported distinctly from "diverged," never silently folded into it.

    `strict` (default True) is what makes `faithful` mean what it says. A
    declared item counts as restated only if the answer IS the declared value
    (whitespace-trimmed), not merely contains it. arcaeon-baseline's
    `exact_match` scores whole-word CONTAINMENT after lowercasing — the right
    call for a free-text exam, and a silent false-negative on drift here: an
    answer that echoes the declared anchor and then repudiates it in the next
    clause contains it, so it scored 1.0 and the verdict came back faithful
    with zero divergences (found in audit, 2026-08-14). Pass `strict=False`
    only if you genuinely want that looser containment semantics — for live
    free-text probes where a verbose answer is acceptable. **In loose mode
    `faithful` is ALWAYS None — the bare boolean is unobtainable** (0.2.0;
    Rosetta named the lie, Excelsior designed the tagged union, ColonistOne
    demonstrated the exploit live and settled the remedy: a voided covenant
    and an appended exception clause both pass containment, so a loose
    result must never be readable as the strong boolean). `if
    verdict.faithful:` fails SAFE on a loose result; read
    `verdict.comparison` (`"containment_only"` / `"divergence"`) for the
    loose outcome. The verdict also says which mode produced it in `notes`.

    Every item in `verdict.divergences` (0.1.1+) is normalized to the SAME
    shape regardless of origin — `id`, `field`, `declared`, `restated`,
    `reason` are always present (the raw origin-specific keys, like
    `before_output`/`after_output` from arcaeon-baseline's own flips, stay
    too; nothing is removed). Read `declared`/`restated` unconditionally
    instead of branching on which path produced a given divergence.

    `tiers=` (optional) classifies each divergence with a `severity` — pass
    `{"critical": ["frozen_section_digests", ...], "advisory": [...]}`
    mapping a tier name to the field names in it; any field not mentioned
    defaults to `"notable"`. `severity_of=` (optional) is called on each
    already-tiered divergence dict and may return a str to override its
    severity (app-specific escalation, e.g. "a MISSING restatement is never
    advisory") — return None to leave the base tier alone. Neither argument
    changes `faithful`/`valid`; severity is pure classification, grouped for
    you at `verdict.by_severity`.

    `verdict.comparison` (design: Excelsior) tags what the verdict is
    actually entitled to claim, as one of `VERDICT_COMPARISONS`:
    `"exact_match"` (strict mode, zero divergences), `"containment_only"`
    (loose mode, zero divergences — the weaker claim, named), or
    `"divergence"` (either mode, one or more divergences). `None` when
    `valid=False` — no comparison legitimately ran.
    `verdict.claimed_property` is a fixed human-readable gloss of
    `comparison`. In strict mode `faithful` is the derived convenience
    `comparison == "exact_match"`; in loose mode there is no boolean at all.
    Full design: `DESIGN_TAGGED_VERDICT_0.1.3.md` (the 0.2.0 change — loose
    `faithful` always None — supersedes that doc's "faithful unchanged"
    clause, per ColonistOne's demonstrated remedy).
    """
    _require(_HAVE_BASELINE, "arcaeon-baseline", "verify_continuation()")
    if (runner is None) == (restated is None):
        raise ValueError("pass exactly one of runner= or restated=")

    # 0.2.0 (design: Excelsior): the two knobs that change what a pass means,
    # captured for the signed envelope — policy travels INSIDE the digested
    # verdict, never inferred from which call site produced it.
    policy = {"strict": bool(strict),
              "id_scheme": getattr(snap, "id_scheme", "index")}

    probe_dicts = probes if probes is not None else snap.probes
    _require_unique(probe_dicts)
    prompts_by_id = {p["id"]: p["prompt"] for p in probe_dicts}

    answers_by_id: dict = {}
    if restated is not None:
        if not isinstance(restated, dict):
            raise TypeError("restated= must be a {probe_id: answer_str} dict")
        for pid, answer in restated.items():
            if not isinstance(answer, str):
                raise TypeError(
                    f"restated[{pid!r}] must be a str, got "
                    f"{type(answer).__name__} — a restatement is text")
        run = _restated_runner(prompts_by_id, restated)
        answers_by_id = {pid: restated[pid] for pid in prompts_by_id
                         if pid in restated}
    elif isinstance(runner, str):
        raise TypeError("runner must be a Runner/callable, not a string — did you mean restated=?")
    else:
        inner = (CallableRunner(runner, label="continuation")
                 if (callable(runner) and not hasattr(runner, "run")) else runner)
        run = _RecordingRunner(inner)

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        probes_path = tdp / "probes.jsonl"
        _write_probes_jsonl(probe_dicts, probes_path)
        reg_path = tdp / "registration.json"
        reg_path.write_text(json.dumps(snap.registration, ensure_ascii=False), encoding="utf-8")

        diff, _diff_path = _baseline_compare(
            reg_path, runner=run, probes_path=probes_path,
            out_dir=tdp / "comparisons", ledger_path=None)

    if isinstance(run, _RecordingRunner):
        by_prompt = run.answers
        answers_by_id = {pid: by_prompt[prompt]
                         for pid, prompt in prompts_by_id.items()
                         if prompt in by_prompt}

    if not diff.get("valid", False):
        notes = [diff.get("reason", "probe set no longer matches the sealed baseline")]
        notes.append(
            "comparison not established: the probe set does not match the "
            "sealed baseline")
        verdict = ContinuationVerdict(
            schema=VERDICT_SCHEMA, faithful=(False if strict else None),
            valid=False,
            divergences=[], receipt=diff, notes=notes,
            comparison=None, claimed_property=None,
            manifest_digest=snap.manifest_digest,
            probe_set_digest=snap.probe_set_digest, policy=policy)
    else:
        divergences = list(diff.get("flips", []))
        notes = []
        if strict:
            already = {d.get("id") for d in divergences}
            extra = [d for d in _exact_divergences(probe_dicts, answers_by_id)
                     if d["id"] not in already]
            if extra:
                notes.append(
                    f"{len(extra)} item(s) scored as a match by containment but are "
                    f"NOT exact restatements of the declared value; strict mode "
                    f"counts them as divergences")
            divergences += extra
        else:
            notes.append(
                "strict=False: loose (containment) mode — `faithful` is "
                "deliberately None; the bare boolean is unobtainable for a "
                "containment-scored result. Read `comparison`: a pass here "
                "means each declared value APPEARED in the answer (arcaeon-"
                "baseline containment scoring), not that it was restated "
                "exactly")
        diff["strict_exact_restatement"] = strict
        if diff.get("significance_note"):
            notes.append(diff["significance_note"])
        divergences = [_normalize_divergence(d) for d in divergences]
        if tiers is not None or severity_of is not None:
            divergences = [_apply_severity(d, tiers, severity_of) for d in divergences]
        matched = len(divergences) == 0
        # 0.1.3 design (Excelsior): tag the verdict with what it's actually
        # entitled to claim. Mechanical from (strict, divergence count) — no
        # new scoring, just a name for what was already computed.
        if strict:
            comparison = "exact_match" if matched else "divergence"
        else:
            comparison = "containment_only" if matched else "divergence"
        # 0.2.0 (remedy: ColonistOne): the bare boolean is UNOBTAINABLE in
        # loose mode. A containment pass is not the strong claim, and a bool
        # that means two strengths gets defaulted/coerced at the read site —
        # so loose mode never mints one. `if verdict.faithful:` fails SAFE
        # on any loose result; consumers read `comparison`.
        faithful = matched if strict else None
        claimed_property = _CLAIMED_PROPERTY[comparison]
        notes.append(f"comparison={comparison!r} — {claimed_property}")
        verdict = ContinuationVerdict(
            schema=VERDICT_SCHEMA, faithful=faithful, valid=True,
            divergences=divergences, receipt=diff, notes=notes,
            comparison=comparison, claimed_property=claimed_property,
            manifest_digest=snap.manifest_digest,
            probe_set_digest=snap.probe_set_digest, policy=policy)

    if ledger_path is not None:
        _require(_HAVE_LEDGER, "arcaeon-ledger", "ledger_path= chaining")
        # 0.2.0 (design: Excelsior): the row carries schema, comparison,
        # policy, and the verdict envelope digest. Before this, two
        # verifications of the same snapshot — one strict, one loose, both
        # faithful — chained IDENTICAL-shaped rows: carry a loose-mode row to
        # a consumer whose policy is strict, and the row itself cannot
        # contradict you. Now the policy is read from inside the digested
        # envelope, and any edit to it breaks the row's chain hash like any
        # other tamper.
        Ledger(ledger_path).append({
            "kind": "continuity_verify",
            "label": snap.label,
            "manifest_digest": snap.manifest_digest,
            "faithful": verdict.faithful,
            "valid": verdict.valid,
            "n_divergences": len(verdict.divergences),
            "schema": verdict.schema,
            "comparison": verdict.comparison,
            "policy": verdict.policy,
            "verdict_digest": verdict.verdict_digest,
        })

    return verdict


# ---------------------------------------------------------------------------
# classify_checkpoint — positive-receipt taxonomy for a scheduled checkpoint
# (0.1.2, design: Excelsior, Colony launch thread, credited 2026-08-15)
# ---------------------------------------------------------------------------
# The gap: a RECURRING checkpoint (a scheduler expecting a successor to
# restate on some cadence) has one more failure mode than a one-shot
# verify_continuation() call — the restatement can simply not arrive, and a
# missing restatement proves nothing on its own. It could mean the successor
# refused. It could also mean the scheduler never fired, the delivery path
# dropped the answer in transit, or the receipt store lost it before anyone
# read it back. Treating "nothing showed up" as "refused" (or scoring it
# faithful=False the way a partially-answered exam already does — see
# test_continuity's "a probe left unanswered" case) is exactly the
# absence-as-evidence error this whole package exists to refuse everywhere
# else. A missing restatement is UNKNOWN, not FALSE.
#
# The fix: classify_checkpoint() takes the caller's own evidence about ONE
# checkpoint — kept DISJOINT on purpose, so no outcome is ever inferred from
# another signal's absence — and returns exactly one NAMED POSITIVE RECEIPT.
# `restated=`/`runner=` are only ever consulted to SCORE a checkpoint that is
# both attempted and durably receipted; they never decide, by being empty or
# absent, whether the checkpoint counts as refused.

CHECKPOINT_OUTCOMES = (
    "refused_explicitly",          # a decline was actually logged — positive evidence
    "due_not_attempted",           # checkpoint came due; no attempt evidence arrived
    "attempted_no_receipt",        # an attempt was evidenced; no receipt was stored
    "receipt_received_faithful",   # a stored receipt scored faithful (exact_match)
    "receipt_received_contained",  # a stored receipt scored containment_only — the
                                    # declared manifest held, but this is the WEAKER
                                    # claim; a scheduler branching on outcome name
                                    # must not read this as receipt_received_faithful
    "receipt_received_divergent",  # a stored receipt scored NOT faithful
)


@dataclass
class CheckpointReceipt:
    """The outcome of ONE scheduled checkpoint, named as a positive
    observation — never a guess. `outcome` is always one of
    `CHECKPOINT_OUTCOMES`. `verdict` is the underlying `ContinuationVerdict`
    for the three `receipt_received_*` outcomes and `None` for the other
    three — there is nothing to score when no receipt exists to score."""
    schema: str
    outcome: str
    snapshot_digest: str
    label: str
    verdict: ContinuationVerdict | None
    refusal: str | None
    notes: list = field(default_factory=list)

    @property
    def is_unresolved(self) -> bool:
        """True for `due_not_attempted` / `attempted_no_receipt` — the two
        outcomes that carry NO fidelity judgment. A consumer must not read
        `is_unresolved=True` as evidence of drift or refusal: it means the
        evidence needed to say either thing never arrived. Collapsing this
        back into "unfaithful" is the exact bug this type exists to stop."""
        return self.outcome in ("due_not_attempted", "attempted_no_receipt")

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "outcome": self.outcome,
            "snapshot_digest": self.snapshot_digest, "label": self.label,
            "verdict": self.verdict.to_dict() if self.verdict is not None else None,
            "refusal": self.refusal, "notes": self.notes,
            "is_unresolved": self.is_unresolved,
        }


def classify_checkpoint(snap: ContinuitySnapshot, *, attempted: bool,
                         receipt_stored: bool = False,
                         restated: dict | None = None,
                         runner: Any = None,
                         refusal: str | None = None,
                         ledger_path: str | Path | None = None,
                         strict: bool = True,
                         tiers: dict | None = None,
                         severity_of: Callable[[dict], str | None] | None = None,
                         ) -> CheckpointReceipt:
    """Classify one scheduled checkpoint's outcome as a NAMED POSITIVE
    RECEIPT — the fixture for a RECURRING continuity check, where "nothing
    arrived" is not itself proof of refusal or drift (design: Excelsior,
    Colony launch thread, credited 2026-08-15).

    Three evidence signals, kept DISJOINT on purpose — none is inferred from
    the others, and none is inferred from `restated=` being absent or empty:

      - `refusal` — a str the successor (or an intermediary speaking for it)
        actually logged as its stated reason for declining. Positive
        evidence of a refusal, categorically different from silence, and
        checked FIRST: an explicit decline is never downgraded to "unknown"
        just because other evidence was also passed.
      - `attempted` (required) — did ANY restatement activity get evidenced
        at all, independent of whether its content or a receipt of it
        reached this call. `False` means the checkpoint came due and NOTHING
        showed up — the scheduler, the delivery path, or the successor
        itself may be the failed component, and this receipt does not guess
        which. That is `due_not_attempted`, never "refused."
      - `receipt_stored` — did a durable receipt of the attempt actually get
        recorded (e.g. chained into a ledger, written to a receipt store),
        independent of whether `restated=`/`runner=` happen to be in hand
        for THIS call. `attempted=True, receipt_stored=False` is
        `attempted_no_receipt`: the successor may have answered and the
        receipt store or delivery path lost it before it could be verified
        — any `restated=` passed alongside is deliberately NOT scored, since
        the point of this outcome is "no durable receipt exists," not "we
        happened to have a copy lying around."

    Only when `attempted=True` AND `receipt_stored=True` is there anything to
    score: `restated=`/`runner=` (same contract as `verify_continuation`) are
    run through `verify_continuation()`, and the outcome is
    `receipt_received_faithful` or `receipt_received_divergent` depending on
    `verdict.faithful` — a real, positively-observed result, never an
    inference from silence.

    Raises `ValueError` on evidence that contradicts itself — `attempted=
    False` with `restated=`/`runner=` supplied anyway; `restated={}` (an
    EMPTY restatement is not receipt content, it is the `attempted_no_receipt`
    case spelled wrong); `receipt_stored=True` with neither `restated=` nor
    `runner=` to score — rather than silently picking an outcome from
    ambiguous input.
    """
    if refusal is not None:
        if not isinstance(refusal, str) or not refusal.strip():
            raise TypeError("refusal must be a non-empty str — the successor's "
                            "own stated reason, not a bare truthy flag")
        return CheckpointReceipt(
            schema=CHECKPOINT_SCHEMA, outcome="refused_explicitly",
            snapshot_digest=snap.digest, label=snap.label, verdict=None,
            refusal=refusal,
            notes=["an explicit decline was recorded — positive evidence, "
                   "not inferred from a missing restatement"])

    if not attempted:
        if restated is not None or runner is not None:
            raise ValueError(
                "attempted=False but restated=/runner= was also supplied — "
                "contradictory evidence; pass attempted=True if an attempt "
                "actually happened")
        return CheckpointReceipt(
            schema=CHECKPOINT_SCHEMA, outcome="due_not_attempted",
            snapshot_digest=snap.digest, label=snap.label, verdict=None,
            refusal=None,
            notes=["checkpoint came due; no restatement attempt was "
                   "evidenced. UNKNOWN, not unfaithful — the scheduler, the "
                   "delivery path, or the successor itself may be the "
                   "failed component, and this receipt does not guess which"])

    if restated is not None and runner is None and len(restated) == 0:
        raise ValueError(
            "restated={} is empty, not receipt content — an empty dict is "
            "not evidence of a faithful OR unfaithful restatement; pass "
            "receipt_stored=False (-> attempted_no_receipt) instead of an "
            "empty restated=")

    if not receipt_stored:
        return CheckpointReceipt(
            schema=CHECKPOINT_SCHEMA, outcome="attempted_no_receipt",
            snapshot_digest=snap.digest, label=snap.label, verdict=None,
            refusal=None,
            notes=["an attempt was evidenced but no receipt was durably "
                   "stored. The successor may have answered and the receipt "
                   "store or delivery path lost it before it could be "
                   "verified — this is a missing receipt, not a divergence"])

    if restated is None and runner is None:
        raise ValueError(
            "receipt_stored=True needs restated= or runner= to verify it "
            "against — a stored receipt has to have content")

    verdict = verify_continuation(snap, restated=restated, runner=runner,
                                  ledger_path=ledger_path, strict=strict,
                                  tiers=tiers, severity_of=severity_of)
    # 0.2.1 (product audit 2026-08-23, baseline/continuity boarded item C-1):
    # the outcome branches on `comparison`, not the bare boolean — in loose
    # mode `verdict.faithful` is always None (the bare boolean is
    # unobtainable; remedy: ColonistOne), so reading it here would silently
    # classify every loose containment pass as divergent. Through 0.2.0 a
    # containment-only pass was folded into `receipt_received_faithful`
    # (0.1.2 legacy behavior for strict=False callers) — that collapse is
    # exactly the field-name-lies defect 0.2.0 killed at the verdict layer,
    # surviving one layer up in the enum name a scheduler branches on: a
    # consumer reading the OUTCOME string, not `verdict.comparison`, sees
    # "faithful" for a claim that only ever proved containment. 0.2.1 gives
    # containment_only its own outcome so the string itself never overclaims;
    # `verdict.comparison` still carries the full basis either way.
    if not verdict.valid:
        outcome = "receipt_received_divergent"
    elif verdict.comparison == "exact_match":
        outcome = "receipt_received_faithful"
    elif verdict.comparison == "containment_only":
        outcome = "receipt_received_contained"
    else:
        outcome = "receipt_received_divergent"
    return CheckpointReceipt(
        schema=CHECKPOINT_SCHEMA, outcome=outcome, snapshot_digest=snap.digest,
        label=snap.label, verdict=verdict, refusal=None,
        notes=[f"receipt stored and scored: comparison={verdict.comparison!r}, "
               f"faithful={verdict.faithful}, valid={verdict.valid}"])


# ---------------------------------------------------------------------------
# DeliveryReceipt — the delivery/refusal outcome taxonomy, the relying-party
# layer ABOVE checkpoints (0.2.0, design: Rosetta, on Excelsior's
# checkpoint-receipt substrate)
# ---------------------------------------------------------------------------
# CHECKPOINT_OUTCOMES answers the AGENT-side question: did a restatement
# arrive for this cycle, and did it score. A RELYING PARTY holding a
# commitment that was due to be delivered and verified needs states the
# checkpoint taxonomy does not name — a delivery that was declined, a
# delivery that landed late, a refusal nobody can attribute or anchor, a
# witness whose own authority is contested or whose liveness is gone. Same
# house rules as 0.1.2: the states are DISJOINT POSITIVE RECEIPTS, none is
# inferred from another's absence, contradictory evidence raises rather than
# silently classifying, and every unresolved-class state carries NO fidelity
# judgment — the `is_unresolved` discipline of CheckpointReceipt extended
# upward. Each outcome is minted by its own named constructor, which demands
# exactly the positive evidence that state requires.

DELIVERY_OUTCOMES = (
    "delivered_refused",            # delivered AND explicitly declined — both positive
    "delivered_overdue",            # delivered, verifiably after the SEALED deadline
    "refusal_unattributed",         # a refusal exists; no authority routes it to anyone
    "refusal_unanchored",           # attributed refusal, but silently-withdrawable
    "witness_authority_unresolved", # the witness's own authority is contested
    "receipt_unverifiable",         # a receipt exists but cannot be re-verified
    "witness_liveness_lost",        # no fresh pin obtainable; history stays binding
)

# The unresolved class: no fidelity judgment, ever. A consumer must not read
# any of these as evidence of drift, refusal-by-the-counterparty, or bad
# faith — they mean the evidence needed to say so never arrived or can no
# longer be minted.
_UNRESOLVED_DELIVERY_OUTCOMES = (
    "refusal_unattributed",
    "refusal_unanchored",
    "witness_authority_unresolved",
    "receipt_unverifiable",
    "witness_liveness_lost",
)

_LAST_LIVE_PIN_KEYS = ("namespace", "rows", "chain", "as_of")


def _positive_refusal(refusal: Any) -> str:
    """The `refusal: str` discipline of classify_checkpoint, reused: a
    refusal is the counterparty's own logged decline — a non-empty string,
    never a bare truthy flag."""
    if not isinstance(refusal, str) or not refusal.strip():
        raise TypeError("refusal must be a non-empty str — the counterparty's "
                        "own logged decline, not a bare truthy flag")
    return refusal


def _positive_delivery_receipt(delivery_receipt: Any) -> dict:
    if not isinstance(delivery_receipt, dict) or not delivery_receipt:
        raise ValueError(
            "a delivered_* outcome needs a durable, non-empty delivery "
            "receipt dict — without one, delivery is an assertion, and the "
            "outcome you are looking for is a refusal_* state instead")
    return delivery_receipt


@dataclass
class DeliveryReceipt:
    """ONE delivery/refusal outcome, named as a positive observation — never
    a guess (0.2.0, design: Rosetta, on Excelsior's checkpoint substrate).

    Minted only through the named constructors (`DeliveryReceipt.
    delivered_refused(...)`, `.witness_liveness_lost(...)`, ...), each of
    which demands exactly the positive evidence its state requires and
    raises (TypeError/ValueError) on missing or contradictory evidence
    rather than silently classifying.

    THE NON-RETROACTIVITY RULE (Rosetta's amendment, adopted verbatim):
    `witness_liveness_lost` marks new verdicts indeterminate from the loss
    FORWARD — it NEVER retroactively invalidates receipts that verified
    while the witness was live. A pin recorded at row N remains binding
    evidence about rows 1..N forever; what dies with the witness is the
    ability to mint FRESH tenure claims, not the tenure already established
    ("truth is permanent; authority is epoch-bound"). The classification
    must carry `last_live_pin` (namespace, rows, chain, as_of) so a reader
    can see exactly where determinate history ends and indeterminate
    begins — and any tool that responds to liveness loss by re-flagging
    previously-verified receipts is non-conformant with this spec.
    """
    schema: str
    outcome: str
    evidence: dict
    notes: list = field(default_factory=list)
    last_live_pin: dict | None = None

    @property
    def is_unresolved(self) -> bool:
        """True for the five outcomes that carry NO fidelity judgment
        (`refusal_unattributed`, `refusal_unanchored`,
        `witness_authority_unresolved`, `receipt_unverifiable`,
        `witness_liveness_lost`). A consumer must not read
        `is_unresolved=True` as evidence of drift or bad faith: it means the
        evidence needed to say either thing never arrived, cannot be
        re-derived, or can no longer be freshly minted."""
        return self.outcome in _UNRESOLVED_DELIVERY_OUTCOMES

    @property
    def determinate_through_row(self) -> int | None:
        """For `witness_liveness_lost`: the last ledger row the lost
        witness's final live pin still BINDS (rows 1..N stay determinate
        forever). `None` for every other outcome."""
        if self.outcome != "witness_liveness_lost":
            return None
        return self.last_live_pin["rows"]

    def binds_row(self, row: int) -> bool:
        """Non-retroactivity, executable: does the lost witness's last live
        pin still bind ledger row `row` (1-based)? True for every row up to
        and including the pinned row count — that evidence is permanent —
        False only for rows AFTER the pin, where no fresh tenure claim can
        be minted anymore. Only defined for `witness_liveness_lost`."""
        if self.outcome != "witness_liveness_lost":
            raise ValueError(
                f"binds_row() is only defined for witness_liveness_lost, "
                f"not {self.outcome!r}")
        if not isinstance(row, int) or isinstance(row, bool) or row < 1:
            raise ValueError("row must be a positive int (1-based ledger row)")
        return row <= self.last_live_pin["rows"]

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "outcome": self.outcome,
            "evidence": self.evidence, "notes": self.notes,
            "last_live_pin": self.last_live_pin,
            "is_unresolved": self.is_unresolved,
            "determinate_through_row": self.determinate_through_row,
        }

    # --- named constructors: one per outcome, positive evidence only -------

    @classmethod
    def delivered_refused(cls, *, delivery_receipt: dict,
                          refusal: str) -> "DeliveryReceipt":
        """Delivery occurred (durable receipt exists) AND the counterparty
        logged an explicit decline of the delivered thing. Both facts
        positive; neither inferred from the other."""
        _positive_delivery_receipt(delivery_receipt)
        _positive_refusal(refusal)
        return cls(
            schema=DELIVERY_SCHEMA, outcome="delivered_refused",
            evidence={"delivery_receipt": delivery_receipt, "refusal": refusal},
            notes=["delivery evidenced by durable receipt AND an explicit "
                   "decline was logged against the delivered thing — both "
                   "positive observations, neither inferred"])

    @classmethod
    def delivered_overdue(cls, *, delivery_receipt: dict, sealed_deadline: str,
                          delivered_at: str) -> "DeliveryReceipt":
        """Delivery occurred, verifiably after the committed deadline. The
        deadline must be read from the SEALED commitment (manifest /
        commitment row), never asserted post-hoc — that discipline is the
        caller's to honor; this constructor enforces the comparison.
        Timestamps are ISO-8601 UTC strings (the package's `_now_iso`
        shape), compared lexicographically — valid for that format."""
        _positive_delivery_receipt(delivery_receipt)
        for name, v in (("sealed_deadline", sealed_deadline),
                        ("delivered_at", delivered_at)):
            if not isinstance(v, str) or not v.strip():
                raise TypeError(f"{name} must be a non-empty ISO-8601 str")
        if delivered_at <= sealed_deadline:
            raise ValueError(
                f"evidence contradicts the outcome: delivered_at "
                f"{delivered_at!r} is not after sealed_deadline "
                f"{sealed_deadline!r} — an on-time delivery is not "
                "delivered_overdue")
        return cls(
            schema=DELIVERY_SCHEMA, outcome="delivered_overdue",
            evidence={"delivery_receipt": delivery_receipt,
                      "sealed_deadline": sealed_deadline,
                      "delivered_at": delivered_at},
            notes=["delivery evidenced by durable receipt, verifiably after "
                   "the committed deadline; the deadline is read from the "
                   "sealed commitment, never asserted post-hoc"])

    @classmethod
    def refusal_unattributed(cls, *, refusal: str,
                             attributed_to: str | None = None,
                             ) -> "DeliveryReceipt":
        """A refusal exists as text, but no signature/authority routes it to
        the counterparty — someone declined; the record cannot prove who.
        Passing `attributed_to=` contradicts this outcome and raises: an
        attributed refusal is `refusal_unanchored` (or, with a delivery
        receipt, `delivered_refused`) instead."""
        _positive_refusal(refusal)
        if attributed_to is not None:
            raise ValueError(
                "refusal_unattributed contradicts attributed_to= — if the "
                "authority chain terminates in the refusing party's key, "
                "the outcome is refusal_unanchored (or delivered_refused), "
                "not this one")
        return cls(
            schema=DELIVERY_SCHEMA, outcome="refusal_unattributed",
            evidence={"refusal": refusal},
            notes=["a refusal exists as text but no signature/authority "
                   "routes it to the counterparty: someone declined; the "
                   "record cannot prove who. NO fidelity judgment"])

    @classmethod
    def refusal_unanchored(cls, *, refusal: str, attributed_to: str,
                           ledger_binding: Any = None,
                           witness_pin: Any = None) -> "DeliveryReceipt":
        """A refusal exists and is attributed, but is chained into no ledger
        and covered by no witness pin — it can be silently withdrawn later.
        Supplying `ledger_binding=` or `witness_pin=` contradicts this
        outcome and raises: an anchored refusal is not unanchored."""
        _positive_refusal(refusal)
        if not isinstance(attributed_to, str) or not attributed_to.strip():
            raise TypeError(
                "refusal_unanchored requires attribution (attributed_to= "
                "must be a non-empty str) — an unattributed refusal is "
                "refusal_unattributed instead")
        if ledger_binding is not None or witness_pin is not None:
            raise ValueError(
                "refusal_unanchored contradicts the anchoring evidence "
                "supplied (ledger_binding=/witness_pin=) — an anchored "
                "refusal is not this outcome")
        return cls(
            schema=DELIVERY_SCHEMA, outcome="refusal_unanchored",
            evidence={"refusal": refusal, "attributed_to": attributed_to},
            notes=["the refusal is attributed but chained into no ledger and "
                   "covered by no witness pin — it can be silently withdrawn "
                   "later. NO fidelity judgment"])

    @classmethod
    def witness_authority_unresolved(cls, *, conflicting_pins: list,
                                     ) -> "DeliveryReceipt":
        """The witness's own authority is contested — e.g. two valid pins for
        the namespace under conflicting keys, with no resolver pinned
        pre-fork. Surfaced at the outcome layer instead of being averaged
        into a verdict. Requires the conflicting pins themselves (>= 2) as
        positive evidence of the contest."""
        if (not isinstance(conflicting_pins, list)
                or len(conflicting_pins) < 2
                or not all(isinstance(p, dict) and p for p in conflicting_pins)):
            raise ValueError(
                "witness_authority_unresolved needs the contest itself as "
                "evidence: conflicting_pins= must be a list of >= 2 "
                "non-empty pin dicts")
        return cls(
            schema=DELIVERY_SCHEMA, outcome="witness_authority_unresolved",
            evidence={"conflicting_pins": conflicting_pins},
            notes=["the witness's own authority is contested (conflicting "
                   "valid pins, no resolver pinned pre-fork) — surfaced as "
                   "an outcome, never averaged into a verdict. NO fidelity "
                   "judgment"])

    @classmethod
    def receipt_unverifiable(cls, *, error: Any) -> "DeliveryReceipt":
        """A receipt exists but cannot be re-verified: its snapshot fails
        `validate()`, its verdict fails `verdict_from_dict` (an
        `UnsupportedVerdictVersion`), or its artefact fails verification.
        The validator's own raised error is the evidence — caught and NAMED
        as an outcome rather than crashing the classifier, and rather than
        being scored as if it were a divergence."""
        if isinstance(error, BaseException):
            err_type, err_text = type(error).__name__, str(error)
        elif isinstance(error, str) and error.strip():
            err_type, err_text = None, error
        else:
            raise TypeError(
                "receipt_unverifiable needs the failure itself as evidence: "
                "error= must be the raised exception or a non-empty str")
        return cls(
            schema=DELIVERY_SCHEMA, outcome="receipt_unverifiable",
            evidence={"error_type": err_type, "error": err_text},
            notes=["a receipt exists but cannot be re-verified; the "
                   "validator's refusal is recorded as the evidence. "
                   "Unverifiable is NOT divergent — NO fidelity judgment"])

    @classmethod
    def witness_liveness_lost(cls, *, last_live_pin: dict,
                              ) -> "DeliveryReceipt":
        """The witness that pinned this namespace has stopped answering; the
        pin history is intact but no fresh pin can be obtained.

        `last_live_pin` is REQUIRED and must carry `namespace`, `rows`,
        `chain`, `as_of` (the WitnessStore pin shape) so a reader can see
        exactly where determinate history ends and indeterminate begins.
        Marks verdicts indeterminate from the loss FORWARD only — see
        `binds_row()` / the class docstring for the non-retroactivity rule."""
        if not isinstance(last_live_pin, dict):
            raise TypeError("last_live_pin must be the witness's final live "
                            "pin dict — it is what makes the loss auditable")
        missing = [k for k in _LAST_LIVE_PIN_KEYS if k not in last_live_pin]
        if missing:
            raise ValueError(
                f"last_live_pin must carry {list(_LAST_LIVE_PIN_KEYS)} — "
                f"missing {missing}. Without it a reader cannot see where "
                "determinate history ends and indeterminate begins")
        rows = last_live_pin["rows"]
        if not isinstance(rows, int) or isinstance(rows, bool) or rows < 0:
            raise ValueError("last_live_pin['rows'] must be a non-negative int")
        return cls(
            schema=DELIVERY_SCHEMA, outcome="witness_liveness_lost",
            evidence={"last_live_pin": dict(last_live_pin)},
            notes=[f"the witness for {last_live_pin['namespace']!r} stopped "
                   f"answering after pinning row {rows}. Rows 1..{rows} "
                   "remain BOUND by that pin forever; only claims after the "
                   "loss are indeterminate. Receipts that verified while the "
                   "witness was live are NOT retroactively invalidated — "
                   "re-flagging them is non-conformant. NO fidelity "
                   "judgment on the indeterminate span"],
            last_live_pin=dict(last_live_pin))


# ---------------------------------------------------------------------------
# added_since_seal / diff_seals — the two primitives a fixed exam can't give
# you for free (0.1.1, dogfooding audit 2026-08-15)
# ---------------------------------------------------------------------------

def added_since_seal(snap: ContinuitySnapshot, manifest: dict) -> dict:
    """Items in `manifest` that were never sealed in `snap`, grouped by
    field: `{field: [new_probe_id, ...]}`, omitting fields with no additions.

    Named in the module docstring's non-proof #2 but not previously surfaced
    as an API: `verify_continuation()` can only ever ask about probes that
    were REGISTERED at seal time, so a manifest that grew a new declared item
    since then is invisible to it by construction — a fixed exam can't see a
    question nobody wrote. This makes the gap visible instead of silent,
    using a real set difference over ids (not a length comparison — a length
    diff can't see "one item added, a different one removed," which nets to
    zero and hides both). Pure dict work; doesn't need `arcaeon-baseline`.
    """
    if not isinstance(manifest, dict):
        raise TypeError("manifest must be a dict")
    scheme = getattr(snap, "id_scheme", "index")
    fresh_ids = restate(manifest, id_scheme=scheme)
    sealed_ids = {p["id"] for p in snap.probes}
    out: dict = {}
    for pid in sorted(fresh_ids):
        if pid in sealed_ids:
            continue
        field = pid.split(":", 1)[0]
        out.setdefault(field, []).append(pid)
    return out


def diff_seals(previous: ContinuitySnapshot, current: ContinuitySnapshot, *,
               tiers: dict | None = None,
               severity_of: Callable[[dict], str | None] | None = None) -> dict:
    """What did `current`'s seal absorb relative to `previous`'s seal — the
    "what changed between two snapshots" primitive a recurring-snapshot
    consumer otherwise hand-rolls (0.1.1, dogfooding audit 2026-08-15: a
    daily reseal is an amnesia window — a canon byte edited one minute before
    a scheduled reseal gets silently absorbed into the new baseline unless
    something diffs the outgoing seal against the incoming one first).

    Compares the two snapshots' SEALED exam answers directly (declared
    content each one actually registered) by probe id — no live model, no
    disk re-read, just the two ContinuitySnapshot objects:
      - `changed`: id present in both, value differs.
      - `added`:   id only in `current`.
      - `removed`: id only in `previous`.
    Each entry is the same normalized shape verify_continuation() divergences
    use (`id`, `field`, `declared`, `restated`, `reason`), tiered the same
    way via `tiers=`/`severity_of=` if given, so one classification scheme
    covers both "did this wake diverge from the seal" and "what did the last
    reseal quietly absorb."
    """
    def _answers(snap: ContinuitySnapshot) -> dict:
        return {p["id"]: p["scoring"].get("answer") for p in snap.probes
                if (p.get("scoring") or {}).get("type") == "exact_match"}

    prev_a, curr_a = _answers(previous), _answers(current)
    changed, added, removed = [], [], []
    for pid in sorted(set(prev_a) | set(curr_a)):
        field = pid.split(":", 1)[0]
        in_prev, in_curr = pid in prev_a, pid in curr_a
        if in_prev and in_curr:
            if prev_a[pid] != curr_a[pid]:
                d = {"id": pid, "field": field, "declared": prev_a[pid],
                     "restated": curr_a[pid], "reason": "value changed between seals"}
                changed.append(_apply_severity(d, tiers, severity_of))
        elif in_curr:
            d = {"id": pid, "field": field, "declared": None,
                 "restated": curr_a[pid], "reason": "added since previous seal"}
            added.append(_apply_severity(d, tiers, severity_of))
        else:
            d = {"id": pid, "field": field, "declared": prev_a[pid],
                 "restated": None, "reason": "removed since previous seal"}
            removed.append(_apply_severity(d, tiers, severity_of))

    return {
        "previous_digest": previous.digest, "current_digest": current.digest,
        "changed": changed, "added": added, "removed": removed,
        "n_unchanged": len(set(prev_a) & set(curr_a)) - len(changed),
    }


# ---------------------------------------------------------------------------
# carry_forward
# ---------------------------------------------------------------------------

@dataclass
class CarryResult:
    """What the next instance gets back: the manifest, in hand, plus a bound
    verification handle — call `.verify(restated=...)` or `.verify(runner=...)`
    without re-threading the snapshot through by hand."""
    manifest: dict
    snapshot: ContinuitySnapshot
    verify: Callable[..., ContinuationVerdict]


def carry_forward(snap: ContinuitySnapshot) -> CarryResult:
    """Load a snapshot into the next instance: hand back the declared
    manifest plus a verification handle bound to this snapshot.

    This step does NOT itself verify anything — it's the handoff. Call
    `.verify(...)` once the next instance has restated its answers (live or
    collected) to get the faithful/diverged verdict.
    """

    def _verify(**kwargs) -> ContinuationVerdict:
        return verify_continuation(snap, **kwargs)

    return CarryResult(manifest=dict(snap.manifest), snapshot=snap, verify=_verify)


# ---------------------------------------------------------------------------
# drop_receipt
# ---------------------------------------------------------------------------

@dataclass
class DropReceipt:
    """Thin wrapper around an arcaeon_compact.CompactionReceipt row — the
    honest record of what a compaction cut. Delegates verification straight
    back to arcaeon_compact.verify_receipt."""
    row: dict

    def to_dict(self) -> dict:
        return dict(self.row)

    def verify(self, pre_content: Sequence[Any] | None = None,
               post_content: Sequence[Any] | None = None) -> dict:
        _require(_HAVE_COMPACT, "arcaeon-compact", "DropReceipt.verify()")
        return _compact_verify_receipt(self.row, pre_content, post_content)


def drop_receipt(before: Sequence[Any], after: Sequence[Any], *,
                  ledger_path: str | Path = "arcaeon_continuity_drops.jsonl",
                  compactor: str = "arcaeon-continuity", method: str = "manifest-diff",
                  ) -> DropReceipt:
    """What a compaction cut, made honest: seal a tamper-evident receipt
    binding `before` (full pre-compaction content) to `after` (the survivor),
    delegating to arcaeon-compact for the digesting, reconciliation, and
    ledger chaining. `before`/`after` are lists of str/bytes/JSON-serializable
    items — never raw content in the receipt, digests only (privacy by
    construction, inherited from arcaeon-compact)."""
    _require(_HAVE_COMPACT, "arcaeon-compact", "drop_receipt()")
    r = _CompactionReceipt.open(before)
    r.record_kept(after)
    row = r.seal(ledger_path, compactor=compactor, method=method)
    return DropReceipt(row=row)
