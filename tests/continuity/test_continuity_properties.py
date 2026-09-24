"""Property-based tests for arcaeon-continuity, using Hypothesis.

`test_continuity.py` proves the specific negative cases (a planted
divergence, a planted drop, a repudiating superset) are caught. This file
generalizes the same claims over ARBITRARY manifest content — unicode,
whitespace, empty strings, varying shapes — instead of a handful of fixed
examples, on the theory that the product claim ("a faithful verdict means
the probes actually matched") should hold for content nobody hand-picked.

Three properties, matching the three load-bearing claims in the module
docstring and CHANGELOG:

  1. ROUND-TRIP FIDELITY. declare(manifest) -> restate exactly -> verify
     must be faithful, for any manifest content this package accepts.
  2. THE REPUDIATION / MUTATION ATTACK. Any mutation of a single sealed
     item's restated answer (that survives whitespace-trimming, i.e. a
     REAL change per `verify_continuation`'s own `strict` semantics) must
     yield faithful=False and must name that item in `divergences`.
  3. checkpoint_refusal's 5-state taxonomy: a missing restatement is ALWAYS
     `due_not_attempted` (the named unknown), never scored as unfaithful —
     for any manifest, not just the one fixed MANIFEST in test_continuity.py.

Run: pytest test_continuity_properties.py
"""
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

import arcaeon.prove.continuity as ac

# --- strategies --------------------------------------------------------------
# Keys are restricted to a plain lowercase+underscore alphabet so no generated
# key can collide with the `key:idx` / `key:content-hash` shapes the library
# itself derives for probe ids (colliding-id fuzzing is covered by the fixed
# example test_snapshot_refuses_colliding_probe_ids in test_continuity.py —
# this file is about VALUE content, not key/id collisions).
_KEY_ALPHABET = "abcdefghijklmnopqrstuvwxyz_"
_keys = st.text(alphabet=_KEY_ALPHABET, min_size=1, max_size=12)

# Arbitrary text: unicode (hypothesis's default text() excludes lone
# surrogates, so this always round-trips through utf-8), whitespace-only
# strings, and the empty string are all in-scope by construction (min_size=0,
# no alphabet restriction).
_values = st.text(min_size=0, max_size=40)

_scalar_field = _values
_list_field = st.lists(_values, min_size=1, max_size=4)
_field_value = st.one_of(_scalar_field, _list_field)

# min_size=1 on the dict guarantees at least one declared item, so we never
# hit "manifest declared zero items" (snapshot()'s own empty-manifest guard,
# already covered as a fixed example by test_snapshot_rejects_empty_manifest).
manifests = st.dictionaries(keys=_keys, values=_field_value, min_size=1, max_size=5)

_slow_ok = settings(deadline=None, max_examples=60,
                     suppress_health_check=[HealthCheck.too_slow])


# --- 1. round-trip fidelity ---------------------------------------------------

@_slow_ok
@given(manifest=manifests)
def test_property_exact_restatement_of_arbitrary_content_is_always_faithful(manifest):
    """declare -> restate exactly (unicode/whitespace/empty and all) -> verify
    must be faithful, valid, with zero divergences. This is the round-trip
    fidelity claim the whole package rests on."""
    snap = ac.snapshot(manifest, label="prop-roundtrip")
    restated = ac.restate(manifest)
    verdict = ac.verify_continuation(snap, restated=restated)
    assert verdict.valid
    assert verdict.faithful, (
        f"exact restatement of declared content should never diverge; "
        f"manifest={manifest!r} divergences={verdict.divergences!r}")
    assert verdict.divergences == []


@_slow_ok
@given(manifest=manifests)
def test_property_restate_ids_always_match_the_sealed_probe_ids(manifest):
    """restate() must derive the identical id set snapshot() sealed, for any
    manifest shape — the two derivations sharing `_list_item_probe_spec` is
    what makes this true; a property test is what catches a future edit to
    one path that forgets the other."""
    snap = ac.snapshot(manifest, label="prop-ids")
    restated = ac.restate(manifest)
    assert sorted(restated) == sorted(p["id"] for p in snap.probes)


@_slow_ok
@given(manifest=manifests)
def test_property_snapshot_digest_is_deterministic(manifest):
    """Same manifest, sealed twice, must produce the same digest — the
    property-test generalization of test_snapshot_round_trips_deterministically."""
    a = ac.snapshot(manifest, label="prop-digest")
    b = ac.snapshot(manifest, label="prop-digest")
    assert a.digest == b.digest
    reloaded = ac.ContinuitySnapshot.from_json(a.to_json())
    assert reloaded.digest == a.digest
    assert reloaded.manifest == a.manifest


# --- 2. the repudiation / mutation attack -------------------------------------

@_slow_ok
@given(manifest=manifests, data=st.data())
def test_property_any_real_mutation_of_a_sealed_item_is_caught(manifest, data):
    """Pick one declared item at random and replace its restated answer with
    ANY string that is a genuine change under `verify_continuation`'s own
    `strict` semantics (differs after whitespace-trimming — see
    `_exact_divergences`'s `got.strip() == want.strip()` comparison, the
    exact rule this test must respect to avoid false failures on a
    trim-only edit). That mutation MUST make the verdict unfaithful and MUST
    name the mutated item's id in `divergences` — generalizes
    test_verify_continuation_catches_a_planted_divergence and the repudiation
    regression guard over arbitrary declared content and arbitrary mutations."""
    snap = ac.snapshot(manifest, label="prop-mutate")
    restated = ac.restate(manifest)
    victim = data.draw(st.sampled_from(sorted(restated)))
    original = restated[victim]
    mutated = data.draw(_values)
    assume(mutated.strip() != original.strip())

    restated[victim] = mutated
    verdict = ac.verify_continuation(snap, restated=restated)

    assert verdict.valid, "only the answer changed, not the probe set"
    assert not verdict.faithful
    ids_seen = {d["id"] for d in verdict.divergences}
    assert victim in ids_seen, (
        f"mutated item {victim!r} not named in divergences: {verdict.divergences!r}")


@_slow_ok
@given(manifest=manifests, data=st.data())
def test_property_whitespace_only_padding_is_not_a_divergence(manifest, data):
    """The flip side of the mutation property, and a real documented
    behavior (`_exact_divergences` trims before comparing): padding a
    declared item's restatement with pure whitespace must NOT be flagged —
    `strict` mode means exact-after-trim, not byte-identical. This pins that
    contract down explicitly so a future tightening of the comparison (e.g.
    someone "fixing" it to be byte-exact) fails a test instead of silently
    changing what `faithful` means."""
    snap = ac.snapshot(manifest, label="prop-whitespace-pad")
    restated = ac.restate(manifest)
    victim = data.draw(st.sampled_from(sorted(restated)))
    pad = data.draw(st.text(alphabet=" \t\n", max_size=5))
    restated[victim] = pad + restated[victim] + pad

    verdict = ac.verify_continuation(snap, restated=restated)
    assert verdict.faithful, (
        f"whitespace-only padding of a declared item should not diverge: "
        f"{verdict.divergences!r}")


# --- 3. checkpoint_refusal's 5-state taxonomy ---------------------------------

@_slow_ok
@given(manifest=manifests)
def test_property_missing_restatement_is_always_due_not_attempted(manifest):
    """THE key taxonomy property. For ANY manifest, a checkpoint with no
    attempt evidenced at all must classify as `due_not_attempted` — the
    named UNKNOWN state — and must never be reachable as
    `receipt_received_divergent` ("unfaithful") or `refused_explicitly`.
    Generalizes test_missing_restatement_is_due_not_attempted_not_unfaithful
    beyond the one fixed MANIFEST fixture."""
    snap = ac.snapshot(manifest, label="prop-checkpoint-missing")
    receipt = ac.classify_checkpoint(snap, attempted=False)
    assert receipt.outcome == "due_not_attempted"
    assert receipt.outcome in ac.CHECKPOINT_OUTCOMES
    assert receipt.is_unresolved is True
    assert receipt.verdict is None
    assert receipt.refusal is None
    assert receipt.outcome not in ("receipt_received_divergent", "refused_explicitly")


@_slow_ok
@given(manifest=manifests)
def test_property_attempted_without_stored_receipt_is_never_scored(manifest):
    """An evidenced attempt with no durably-stored receipt must classify as
    `attempted_no_receipt` — carrying no fidelity judgment — even when
    perfectly-faithful restated content happens to be sitting right there in
    the call. The outcome names "no durable receipt exists," never
    "we happened to have a copy," for any manifest/content combination."""
    snap = ac.snapshot(manifest, label="prop-checkpoint-unstored")
    restated = ac.restate(manifest)
    receipt = ac.classify_checkpoint(snap, attempted=True, receipt_stored=False,
                                     restated=restated)
    assert receipt.outcome == "attempted_no_receipt"
    assert receipt.outcome in ac.CHECKPOINT_OUTCOMES
    assert receipt.is_unresolved is True
    assert receipt.verdict is None


@_slow_ok
@given(manifest=manifests)
def test_property_checkpoint_outcome_is_always_named_and_correctly_resolved(manifest):
    """Across all four reachable evidence shapes (refused / not-attempted /
    attempted-unstored / attempted-and-stored-faithful), the outcome is
    always one of the five named states, and `is_unresolved` always agrees
    with whether a `verdict` was actually produced — no outcome should ever
    carry a verdict while claiming unresolved, or vice versa."""
    snap = ac.snapshot(manifest, label="prop-checkpoint-all")
    restated = ac.restate(manifest)
    for kwargs in (
        {"attempted": False},
        {"attempted": False, "refusal": "declining for this property case"},
        {"attempted": True, "receipt_stored": False, "restated": restated},
        {"attempted": True, "receipt_stored": True, "restated": restated},
    ):
        receipt = ac.classify_checkpoint(snap, **kwargs)
        assert receipt.outcome in ac.CHECKPOINT_OUTCOMES
        if receipt.is_unresolved:
            assert receipt.verdict is None
        else:
            # refused_explicitly also carries verdict=None (nothing to
            # score, per classify_checkpoint's docstring) — only the two
            # receipt_received_* outcomes actually carry a verdict.
            if receipt.outcome.startswith("receipt_received_"):
                assert receipt.verdict is not None


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
