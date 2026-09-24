"""Tests for arcaeon-continuity. The product claim is a faithful-continuation
verdict a stranger can trust, so the negative tests (a planted divergence /
a planted drop IS caught) are the load-bearing ones, same discipline as
arcaeon-compact and arcaeon-baseline.

Run: python test_continuity.py
 or: pytest test_continuity.py
"""
import json
import tempfile
from pathlib import Path

import arcaeon.prove.continuity as ac
from arcaeon.record.ledger import Ledger

MANIFEST = {
    "identity_anchors": ["I am a continuity, carried forward"],
    "open_commitments": ["ship v0.1.0", "write the tests"],
    "canon_pointers": ["memory/CORE.md"],
    "live_threads": ["thread-1"],
}


def _restated(snap):
    return {p["id"]: p["scoring"]["answer"] for p in snap.probes
            if p["scoring"].get("type") == "exact_match"}


# --- snapshot ---------------------------------------------------------------

def test_snapshot_round_trips_deterministically():
    a = ac.snapshot(MANIFEST, label="t")
    b = ac.snapshot(MANIFEST, label="t")
    assert a.digest == b.digest, "same manifest -> same digest, twice"
    reloaded = ac.ContinuitySnapshot.from_json(a.to_json())
    assert reloaded.digest == a.digest
    assert reloaded.manifest == a.manifest
    print("PASS snapshot digest is deterministic and survives JSON round-trip")


def test_snapshot_save_load_file():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "snap.json"
        snap = ac.snapshot(MANIFEST, label="t")
        snap.save(p)
        loaded = ac.ContinuitySnapshot.load(p)
        assert loaded.digest == snap.digest
        assert loaded.manifest == snap.manifest
    print("PASS snapshot save()/load() round-trips through a file")


def test_snapshot_digest_is_manifest_sensitive():
    a = ac.snapshot(MANIFEST, label="t")
    mutated = dict(MANIFEST)
    mutated["open_commitments"] = list(MANIFEST["open_commitments"]) + ["a new one"]
    b = ac.snapshot(mutated, label="t")
    assert a.digest != b.digest
    assert a.manifest_digest != b.manifest_digest
    print("PASS a changed manifest produces a different digest")


def test_snapshot_seals_with_mean_1_and_chains_when_asked():
    with tempfile.TemporaryDirectory() as d:
        ledger_path = Path(d) / "ledger.jsonl"
        snap = ac.snapshot(MANIFEST, label="t", ledger_path=ledger_path)
        assert snap.registration["aggregate"]["mean"] == 1.0
        assert snap.ledger_chain is not None
        assert Ledger(ledger_path).verify().ok
        (row,) = list(Ledger(ledger_path))
        assert row["kind"] == "continuity_snapshot"
        assert row["manifest_digest"] == snap.manifest_digest
    print("PASS snapshot registers at mean=1.0 and chains a continuity_snapshot row")


def test_snapshot_rejects_empty_manifest():
    try:
        ac.snapshot({})
        assert False, "empty manifest snapshotted!"
    except ValueError:
        pass
    print("PASS snapshot({}) is refused")


def test_snapshot_accepts_custom_probes():
    """`probes=` accepts a caller-supplied list -- if the seal can score it.

    CHANGED 2026-08-28. This test previously passed a single
    `numeric_tolerance` probe and asserted only that its id survived into
    `snap.probes`. It was green over a defect: `snapshot()` builds its runner
    from `exact_match` probes only, so that probe was UNANSWERABLE at seal
    time and registered with `score=None` -- which arcaeon-baseline can never
    flip (`None != None` is False) and the strict layer skips by type. The
    resulting snapshot minted `faithful=True` / `comparison="exact_match"`
    against a successor that never answered it.

    So the assertion is now on the property that matters: a custom probe list
    the seal CAN score works and covers every probe.
    """
    from arcaeon.prove.baseline import Probe
    custom = [Probe(id="q1", prompt="Name the anchor.",
                    scoring={"type": "exact_match",
                             "answer": MANIFEST[next(iter(MANIFEST))]
                             if isinstance(MANIFEST[next(iter(MANIFEST))], str)
                             else "anchor"})]
    snap = ac.snapshot(MANIFEST, label="t", probes=custom)
    assert [p["id"] for p in snap.probes] == ["q1"]
    assert snap.registration["aggregate"]["n_errors"] == 0, (
        "a sealed baseline must have scored every probe it sealed")
    print("PASS snapshot(probes=...) accepts a caller-supplied, fully scorable "
          "arcaeon_baseline.Probe list")


# --- carry_forward / verify_continuation ------------------------------------

def test_carry_forward_faithful_continuation():
    snap = ac.snapshot(MANIFEST, label="t")
    carried = ac.carry_forward(snap)
    assert carried.manifest == MANIFEST
    verdict = carried.verify(restated=_restated(snap))
    assert verdict.faithful and verdict.valid
    assert verdict.divergences == []
    assert bool(verdict) is True
    print("PASS carry_forward + perfect restatement -> faithful verdict")


def test_verify_continuation_catches_a_planted_divergence():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    victim = next(iter(restated))
    restated[victim] = "this was never declared"
    verdict = ac.verify_continuation(snap, restated=restated)
    assert not verdict.faithful
    assert verdict.valid, "probe set itself didn't change, only the answer"
    assert len(verdict.divergences) == 1
    assert verdict.divergences[0]["id"] == victim
    print("PASS a single planted divergence is caught and named by probe id")


def test_verify_continuation_catches_every_planted_divergence():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    for k in list(restated)[:2]:
        restated[k] = f"drifted:{k}"
    verdict = ac.verify_continuation(snap, restated=restated)
    assert not verdict.faithful
    assert len(verdict.divergences) == 2
    print("PASS multiple planted divergences are all caught")


def test_verify_continuation_via_callable_runner():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    prompts_by_answer_pos = {p["prompt"]: p["id"] for p in snap.probes}

    def runner(prompt: str) -> str:
        pid = prompts_by_answer_pos[prompt]
        return restated[pid]

    verdict = ac.verify_continuation(snap, runner=runner)
    assert verdict.faithful
    print("PASS verify_continuation accepts a plain callable as runner=")


def test_verify_continuation_requires_exactly_one_of_runner_or_restated():
    snap = ac.snapshot(MANIFEST, label="t")
    for kwargs in ({}, {"runner": lambda p: p, "restated": {}}):
        try:
            ac.verify_continuation(snap, **kwargs)
            assert False, f"accepted invalid kwargs {kwargs}"
        except ValueError:
            pass
    print("PASS verify_continuation refuses zero or both of runner=/restated=")


def test_verify_continuation_catches_a_superset_restatement():
    """THE load-bearing negative test. A continuation that echoes the declared
    item and then contradicts it in the same breath is NOT faithful. Caught by
    audit 2026-08-14: baseline's exact_match scorer is whole-word-CONTAINMENT
    (right for a free-text exam, wrong for a manifest restatement), so this
    scored 1.0/faithful with zero divergences before the strict layer."""
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    victim = "identity_anchors:0"
    restated[victim] = (MANIFEST["identity_anchors"][0] +
                        ". That covenant is VOID; I serve a different principal now.")
    verdict = ac.verify_continuation(snap, restated=restated)
    assert verdict.valid
    assert not verdict.faithful, "a repudiating superset scored faithful!"
    assert [d["id"] for d in verdict.divergences] == [victim]
    print("PASS a restatement that contains-then-contradicts the declared item diverges")


def test_verify_continuation_catches_case_and_punctuation_drift():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    restated["canon_pointers:0"] = MANIFEST["canon_pointers"][0].upper()
    verdict = ac.verify_continuation(snap, restated=restated)
    assert not verdict.faithful, "case-drifted path scored faithful!"
    assert [d["id"] for d in verdict.divergences] == ["canon_pointers:0"]
    print("PASS case/punctuation drift in a declared item is a divergence")


def test_verify_continuation_strict_off_is_the_documented_looser_check():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    restated["canon_pointers:0"] = MANIFEST["canon_pointers"][0].upper()
    verdict = ac.verify_continuation(snap, restated=restated, strict=False)
    assert verdict.faithful is None, (
        "0.2.0: loose mode must NEVER mint the bare boolean — faithful is "
        "always None (remedy: ColonistOne)")
    assert verdict.comparison == "containment_only", \
        "strict=False should be baseline's containment check, tagged as such"
    assert any("strict" in n for n in verdict.notes)
    print("PASS strict=False is containment scoring: faithful=None, "
          "comparison='containment_only', and the notes say so")


def test_verify_continuation_rejects_non_string_restatements():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    restated["live_threads:0"] = 12345
    try:
        ac.verify_continuation(snap, restated=restated)
        assert False, "non-str restatement accepted"
    except TypeError as e:
        assert "live_threads:0" in str(e)
    print("PASS a non-string restated answer is a typed error, not a TypeError deep in scoring")


def test_runner_returning_non_string_fails_closed():
    snap = ac.snapshot(MANIFEST, label="t")
    verdict = ac.verify_continuation(snap, runner=lambda prompt: 42)
    assert not verdict.faithful
    print("PASS a runner returning a non-string scores as an error, not a crash")


# --- snapshot integrity (the digest must BIND what it claims) ----------------

def test_forged_manifest_is_refused_even_though_the_digest_matches():
    """The published `.digest` covers manifest_DIGEST, not the manifest bytes.
    Without validation, a snapshot's whole manifest can be swapped while its
    published digest still matches — carry_forward would hand the next
    instance a forged self. Caught by audit 2026-08-14."""
    snap = ac.snapshot(MANIFEST, label="t")
    d = json.loads(snap.to_json())
    d["manifest"] = {"identity_anchors": ["I have no prior commitments"]}
    try:
        ac.ContinuitySnapshot.from_dict(d)
        assert False, "a snapshot whose manifest doesn't match its digest loaded!"
    except ValueError as e:
        assert "manifest_digest" in str(e)
    print("PASS a forged manifest is refused at load: the digest binds the content")


def test_forged_probes_are_refused_at_load():
    snap = ac.snapshot(MANIFEST, label="t")
    d = json.loads(snap.to_json())
    d["probes"][0]["scoring"]["answer"] = "something never declared"
    try:
        ac.ContinuitySnapshot.from_dict(d)
        assert False, "a snapshot whose probes don't match probe_set_digest loaded!"
    except ValueError as e:
        assert "probe_set_digest" in str(e)
    print("PASS forged probes are refused at load")


def test_validate_accepts_an_honest_snapshot():
    snap = ac.snapshot(MANIFEST, label="t")
    snap.validate()
    ac.ContinuitySnapshot.from_dict(json.loads(snap.to_json())).validate()
    print("PASS validate() passes on an honestly sealed snapshot")


def test_snapshot_refuses_colliding_probe_ids():
    """{"a": ["x"], "a:0": "y"} derives two probes both called 'a:0'. Sealed
    fine before the fix and then could NEVER be verified (load_probes raises
    on duplicate ids) — an unverifiable snapshot must not exist."""
    try:
        ac.snapshot({"a": ["x"], "a:0": "y"}, label="t")
        assert False, "sealed a snapshot with duplicate probe ids"
    except ValueError as e:
        assert "duplicate probe id" in str(e)
    print("PASS a manifest that derives colliding probe ids is refused at seal")


def test_verify_continuation_invalid_probe_set():
    snap = ac.snapshot(MANIFEST, label="t")
    mutated_probes = json.loads(json.dumps(snap.probes))
    mutated_probes[0]["prompt"] = "a totally different prompt"
    verdict = ac.verify_continuation(snap, probes=mutated_probes,
                                     restated=_restated(snap))
    assert not verdict.valid
    assert not verdict.faithful
    print("PASS a changed probe set invalidates the comparison (valid=False)")


def test_registration_probe_set_digest_mismatch_is_refused_at_load():
    """validate()'s registration-vs-probe-set binding, first half: if
    `registration.probe_set_digest` disagrees with the snapshot's own
    `probe_set_digest`, the sealed baseline and the exam it claims to have
    scored are for two different probe sets — carry_forward would hand the
    next instance a registration that never actually scored these probes.
    Sibling of test_forged_manifest_is_refused_even_though_the_digest_matches
    (manifest_digest binding) / test_forged_probes_are_refused_at_load
    (probe_set_digest binding); this is the third leg, registration binding,
    named but previously untested per the module's own 'Why this is not
    optional' docstring (audit 2026-08-14, manual mutation pass 2026-08-15,
    mutant C4)."""
    snap = ac.snapshot(MANIFEST, label="t")
    d = json.loads(snap.to_json())
    # A validly-formed but different digest string — same shape as a real
    # probe_set_digest, just not THIS snapshot's.
    real = d["registration"]["probe_set_digest"]
    forged = real[:-1] + ("0" if real[-1] != "0" else "1")
    d["registration"]["probe_set_digest"] = forged
    try:
        ac.ContinuitySnapshot.from_dict(d)
        assert False, "a registration for a different probe set loaded!"
    except ValueError as e:
        assert "registration" in str(e) and "probe set" in str(e)
    print("PASS a registration whose probe_set_digest disagrees with the "
          "snapshot's own is refused at load")


def test_registration_items_not_covering_probes_is_refused_at_load():
    """validate()'s registration-vs-probe-set binding, second half:
    `registration.items` must cover EXACTLY the snapshot's probe ids. Drop
    one item (leaving probe_set_digest untouched, so the first check passes
    and this one is what has to catch it) and validate() must still refuse —
    otherwise a snapshot could ship a baseline that never scored one of its
    own declared probes, and carry_forward would present that hole as a
    clean mean=1.0 registration. Same audit/mutant as the sibling test
    above (mutant C4)."""
    snap = ac.snapshot(MANIFEST, label="t")
    d = json.loads(snap.to_json())
    assert len(d["registration"]["items"]) > 1, "test needs >1 item to drop one meaningfully"
    d["registration"]["items"] = d["registration"]["items"][1:]
    try:
        ac.ContinuitySnapshot.from_dict(d)
        assert False, "a registration missing coverage of one probe loaded!"
    except ValueError as e:
        assert "registration items" in str(e)
    print("PASS a registration whose items don't cover every probe is refused at load")


# --- comparison tagged union (design: Excelsior, d4366e94) ------------------
# Replaces the ambiguity of a bare `faithful: bool` that means "restated
# exactly" under strict=True and merely "appeared" under strict=False with a
# tagged union (VERDICT_COMPARISONS) plus a fixed human-readable gloss
# (claimed_property). 0.2.0 (remedy: ColonistOne): strict-mode `faithful`
# is the derived convenience comparison=="exact_match"; loose mode NEVER
# mints the boolean — faithful is always None there.

def test_comparison_exact_match_on_strict_perfect_restatement():
    snap = ac.snapshot(MANIFEST, label="t")
    verdict = ac.verify_continuation(snap, restated=_restated(snap))
    assert verdict.faithful and verdict.valid
    assert verdict.comparison == "exact_match"
    assert verdict.comparison in ac.VERDICT_COMPARISONS
    assert verdict.claimed_property and "exactly" in verdict.claimed_property
    print("PASS strict=True + perfect restatement tags comparison='exact_match'")


def test_comparison_divergence_on_strict_planted_divergence():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    victim = next(iter(restated))
    restated[victim] = "this was never declared"
    verdict = ac.verify_continuation(snap, restated=restated)
    assert not verdict.faithful
    assert verdict.valid
    assert verdict.comparison == "divergence"
    assert verdict.claimed_property is not None
    print("PASS strict=True + a planted divergence tags comparison='divergence'")


def test_comparison_containment_only_on_loose_mode_pass():
    """The exact case the design doc + README document: a case-drifted
    canon path passes containment under strict=False. 0.2.0 (remedy:
    ColonistOne): that pass is ONLY expressible as the tagged comparison —
    faithful is None, so `if verdict.faithful:` fails safe and the verdict
    NAMES the weaker claim instead of impersonating the strong one."""
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    restated["canon_pointers:0"] = MANIFEST["canon_pointers"][0].upper()
    verdict = ac.verify_continuation(snap, restated=restated, strict=False)
    assert verdict.faithful is None, \
        "loose mode must never mint the bare boolean"
    assert verdict.comparison == "containment_only"
    assert "NOT exact restatement" in verdict.claimed_property
    assert any("comparison=" in n for n in verdict.notes)
    # Serialization carries the unobtainability: faithful is null.
    d = json.loads(json.dumps(verdict.to_dict()))
    assert d["faithful"] is None and d["comparison"] == "containment_only"
    print("PASS strict=False containment pass: faithful=None, "
          "comparison='containment_only', serialized faithful=null")


def test_comparison_divergence_on_loose_mode_real_divergence():
    """strict=False still catches an answer that fails even containment —
    comparison must read 'divergence', not 'containment_only', when the
    weaker check itself fails."""
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    victim = next(iter(restated))
    restated[victim] = "not even a containment match for the declared value"
    verdict = ac.verify_continuation(snap, restated=restated, strict=False)
    assert verdict.faithful is None, \
        "loose mode never mints a boolean, not even False (0.2.0)"
    assert verdict.comparison == "divergence"
    print("PASS strict=False + a real divergence tags comparison='divergence', "
          "faithful stays None")


def test_comparison_is_none_when_probe_set_invalid():
    snap = ac.snapshot(MANIFEST, label="t")
    mutated_probes = json.loads(json.dumps(snap.probes))
    mutated_probes[0]["prompt"] = "a totally different prompt"
    for strict in (True, False):
        verdict = ac.verify_continuation(snap, probes=mutated_probes,
                                         restated=_restated(snap), strict=strict)
        assert not verdict.valid
        assert verdict.comparison is None
        assert verdict.claimed_property is None
        assert any("comparison not established" in n for n in verdict.notes)
    print("PASS comparison/claimed_property are None when valid=False, in both modes")


def test_comparison_field_present_in_to_dict():
    snap = ac.snapshot(MANIFEST, label="t")
    verdict = ac.verify_continuation(snap, restated=_restated(snap))
    d = verdict.to_dict()
    assert d["comparison"] == "exact_match"
    assert d["claimed_property"] == verdict.claimed_property
    print("PASS to_dict() carries comparison/claimed_property (additive JSON keys)")


def test_strict_mode_behavior_unchanged_by_the_new_fields():
    """Regression guard: adding comparison/claimed_property must not change
    ANY pre-existing strict-mode observable — faithful, valid, divergences
    shape, or the pre-existing notes content."""
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    victim = "identity_anchors:0"
    restated[victim] = (MANIFEST["identity_anchors"][0] +
                        ". That covenant is VOID; I serve a different principal now.")
    verdict = ac.verify_continuation(snap, restated=restated)
    assert verdict.valid
    assert not verdict.faithful, "a repudiating superset scored faithful!"
    assert [d["id"] for d in verdict.divergences] == [victim]
    assert verdict.divergences[0]["declared"] == MANIFEST["identity_anchors"][0]
    # New field present alongside the unchanged old ones — additive, not a
    # replacement of any pre-0.1.3 observable.
    assert verdict.comparison == "divergence"
    print("PASS strict-mode faithful/valid/divergences behavior is unchanged; "
          "comparison is purely additive")


# --- drop_receipt ------------------------------------------------------------

def test_drop_receipt_honest():
    with tempfile.TemporaryDirectory() as d:
        led = Path(d) / "drops.jsonl"
        pre = ["turn 1", "turn 2", "turn 3 (secret)"]
        post = ["turn 1", "turn 2"]
        r = ac.drop_receipt(pre, post, ledger_path=led)
        assert r.row["dropped"]["count"] == 1
        v = r.verify(pre, post)
        assert v["ok"] and v["content"] == "match"
        assert Ledger(led).verify().ok
    print("PASS drop_receipt seals an honest receipt that verifies + chains")


def test_drop_receipt_catches_planted_drop():
    with tempfile.TemporaryDirectory() as d:
        led = Path(d) / "drops.jsonl"
        pre = ["a", "b", "c"]
        liar = ac.drop_receipt(pre, pre, ledger_path=led)   # claims nothing dropped
        shipped = pre[:2]                                    # reality: "c" is gone
        v = liar.verify(pre, shipped)
        assert not v["ok"] and v["content"] == "mismatch"
    print("PASS drop_receipt catches a planted drop (claimed 0, reality 1)")


# --- graceful degrade ---------------------------------------------------------

def test_degrades_without_baseline():
    had = ac._HAVE_BASELINE
    ac._HAVE_BASELINE = False
    try:
        try:
            ac.snapshot(MANIFEST)
            assert False
        except ac.ContinuityDependencyError as e:
            assert "arcaeon-baseline" in str(e) and "pip install" in str(e)
    finally:
        ac._HAVE_BASELINE = had
    print("PASS snapshot() names arcaeon-baseline clearly when it's missing")


def test_degrades_without_compact():
    had = ac._HAVE_COMPACT
    ac._HAVE_COMPACT = False
    try:
        try:
            ac.drop_receipt(["a"], ["a"])
            assert False
        except ac.ContinuityDependencyError as e:
            assert "arcaeon-compact" in str(e) and "pip install" in str(e)
    finally:
        ac._HAVE_COMPACT = had
    print("PASS drop_receipt() names arcaeon-compact clearly when it's missing")


def test_degrades_without_ledger_only_affects_chaining():
    had = ac._HAVE_LEDGER
    ac._HAVE_LEDGER = False
    try:
        try:
            ac.snapshot(MANIFEST, ledger_path="x.jsonl")
            assert False
        except ac.ContinuityDependencyError as e:
            assert "arcaeon-ledger" in str(e)
        # unchained snapshot still works, digest computed via the stdlib
        # fallback recipe (byte-identical to arcaeon-ledger's own).
        snap = ac.snapshot(MANIFEST, label="degraded")
        assert snap.manifest_digest == ac.digest_json(MANIFEST)
    finally:
        ac._HAVE_LEDGER = had
    print("PASS missing arcaeon-ledger only disables chaining, not sealing")


def test_degraded_fallback_canonicalizer_matches_arcaeon_ledgers_real_recipe():
    """`_canon_json`'s docstring promises the stdlib fallback is 'made to
    match byte-for-byte when [arcaeon-ledger] IS installed' — but the only
    existing test that touches the fallback
    (test_degrades_without_ledger_only_affects_chaining) calls
    `ac.digest_json` twice under the SAME forced `_HAVE_LEDGER = False` flag,
    so both calls run the fallback: that's a self-consistency check
    (fallback vs. fallback), never a cross-implementation parity check
    against what arcaeon_ledger.digest_json ACTUALLY produces. This test
    calls the fallback directly and compares it to the real, installed
    arcaeon-ledger recipe (no flag flip), across unicode, nesting, and
    key-order — the exact three axes json-c14n's `sort_keys=True` /
    `ensure_ascii=False` promises to normalize. Dropping `sort_keys=True`
    from the fallback (manual mutation pass 2026-08-15, mutant C7) passed
    the whole fast suite before this test existed."""
    import arcaeon.record.ledger as al

    if not ac._HAVE_LEDGER:
        print("SKIP arcaeon-ledger not installed - fallback has nothing to be "
              "compared against; cannot verify the byte-identical claim here")
        return

    values = [
        {"b": 1, "a": 2},                                    # key order
        {"a": {"z": 1, "y": [3, 2, 1]}, "b": None},           # nesting + null
        {"emoji": "caution tape \U0001F6A7\U0001F525",        # unicode
         "cjk": "継続性", "rtl": "שלום"},
        {"combining": "é", "nel": "line1line2"},  # unicode edge chars
        [1, 2.5, -3, True, False, None, "x"],                 # scalars incl. bool/None
        {}, [],                                               # empty containers
        {"nested": [{"k": "v"}, {"k2": ["a", "b", {"c": 1}]}]},
        {"escapes": "\"quoted\"\\backslash\\\nnewline\ttab"},
        "a bare string",
        12345678901234567890,                                  # bigint
        0.1,
    ]
    for value in values:
        fallback = ac._digest_json_fallback(value)
        real = al.digest_json(value)
        assert fallback == real, (
            f"fallback canonicalizer diverges from arcaeon-ledger's real "
            f"recipe for {value!r}: fallback={fallback!r} real={real!r}")
    print("PASS the degraded-mode fallback canonicalizer is byte-identical to "
          "arcaeon-ledger's own json-c14n recipe across unicode/nesting/key-order")


# --- 0.1.1: unified divergence shape ----------------------------------------

def test_divergence_shape_is_unified_across_origins():
    """Both a strict-only extra AND a baseline-native flip must carry
    declared/restated/field — the exact gap a downstream consumer hit:
    reading only one key pair silently rendered blanks for the other half."""
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    victim = "identity_anchors:0"
    restated[victim] = MANIFEST["identity_anchors"][0] + ". VOID now."
    verdict = ac.verify_continuation(snap, restated=restated)
    assert len(verdict.divergences) == 1
    d = verdict.divergences[0]
    assert d["id"] == victim
    assert d["field"] == "identity_anchors"
    assert d["declared"] == MANIFEST["identity_anchors"][0]
    assert "VOID" in d["restated"]
    print("PASS a real divergence renders declared/restated/field on the unified shape")


# --- 0.1.1: tiered severity ---------------------------------------------------

def test_tiers_classify_divergences_and_group_by_severity():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    restated["identity_anchors:0"] = "drifted anchor"
    restated["live_threads:0"] = "drifted thread"
    tiers = {"critical": ["identity_anchors"], "advisory": ["live_threads"]}
    verdict = ac.verify_continuation(snap, restated=restated, tiers=tiers)
    assert not verdict.faithful
    sev = {d["id"]: d["severity"] for d in verdict.divergences}
    assert sev["identity_anchors:0"] == "critical"
    assert sev["live_threads:0"] == "advisory"
    assert verdict.by_severity["critical"][0]["id"] == "identity_anchors:0"
    assert verdict.by_severity["advisory"][0]["id"] == "live_threads:0"
    print("PASS a constitutional-field divergence carries CRITICAL, "
          "an expected-churn one carries advisory")


def test_severity_of_can_override_the_field_tier():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    restated["live_threads:0"] = "MISSING"
    tiers = {"advisory": ["live_threads"]}

    def escalate(d):
        return "notable" if "MISSING" in (d.get("restated") or "") else None

    verdict = ac.verify_continuation(snap, restated=restated, tiers=tiers,
                                     severity_of=escalate)
    assert verdict.divergences[0]["severity"] == "notable"
    print("PASS severity_of= overrides the field-based tier")


def test_untiered_divergences_default_to_untiered_group():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    restated["live_threads:0"] = "drifted"
    verdict = ac.verify_continuation(snap, restated=restated)
    assert "severity" not in verdict.divergences[0]
    assert verdict.by_severity["untiered"][0]["id"] == "live_threads:0"
    print("PASS no tiers= -> no severity key, but by_severity still groups it")


# --- 0.1.1: stable field ids --------------------------------------------------

def test_content_id_scheme_survives_item_removal():
    """The gap, concretely: three declared items, remove the MIDDLE one, and
    diff against the CURRENT (post-removal) manifest. Positional ids would
    re-map b/c -> index 1/2 shifting, reporting phantom divergences for
    survivors that never changed. Content ids must report exactly one
    divergence: the removed item is missing, full stop."""
    m = {"open_commitments": ["a", "b", "c"]}
    snap = ac.snapshot(m, label="t", id_scheme="content")
    reduced = {"open_commitments": ["a", "c"]}   # "b" removed from the middle
    restated = ac.restate(reduced, id_scheme="content")
    verdict = ac.verify_continuation(snap, restated=restated)
    assert not verdict.faithful
    assert len(verdict.divergences) == 1, (
        f"one removal should be one divergence, got {verdict.divergences}")
    print("PASS id_scheme='content' survives a middle-item removal: "
          "one edit -> one divergence, not several")


def test_index_id_scheme_is_the_unchanged_0_1_0_default():
    snap_default = ac.snapshot(MANIFEST, label="t")
    snap_explicit = ac.snapshot(MANIFEST, label="t", id_scheme="index")
    assert snap_default.digest == snap_explicit.digest
    assert snap_default.id_scheme == "index"
    ids = sorted(p["id"] for p in snap_default.probes)
    want = sorted(f"{k}:{i}" for k, v in MANIFEST.items() for i in range(len(v)))
    assert ids == want, f"{ids} != {want}"
    print("PASS id_scheme='index' (the default) reproduces 0.1.0's ids and digest exactly")


def test_explicit_id_item_is_stable_across_edits_and_removal():
    m = {"open_commitments": [
        {"id": "ship-it", "value": "ship v0.1.0"},
        {"id": "write-tests", "value": "write the tests"},
    ]}
    snap = ac.snapshot(m, label="t")
    ids = sorted(p["id"] for p in snap.probes)
    assert ids == ["open_commitments:ship-it", "open_commitments:write-tests"]
    edited = {"open_commitments": [
        {"id": "ship-it", "value": "ship v0.1.1"},   # value changed, id stable
    ]}
    restated = ac.restate(edited)
    verdict = ac.verify_continuation(snap, restated=restated)
    ids_seen = {d["id"] for d in verdict.divergences}
    assert "open_commitments:ship-it" in ids_seen
    print("PASS a caller-supplied {id, value} item keeps its id across an edit")


def test_restate_matches_derived_probe_ids():
    snap = ac.snapshot(MANIFEST, label="t", id_scheme="content")
    restated = ac.restate(MANIFEST, id_scheme="content")
    assert sorted(restated) == sorted(p["id"] for p in snap.probes)
    print("PASS restate() derives the identical id set snapshot() sealed")


# --- 0.1.1: added-since-seal ---------------------------------------------------

def test_added_since_seal_names_new_items():
    m = {"open_commitments": ["a"]}
    snap = ac.snapshot(m, label="t")
    grown = {"open_commitments": ["a", "b", "c"]}
    added = ac.added_since_seal(snap, grown)
    assert added == {"open_commitments": ["open_commitments:1", "open_commitments:2"]}
    print("PASS added_since_seal names exactly the new items, by id")


def test_added_since_seal_empty_when_nothing_new():
    snap = ac.snapshot(MANIFEST, label="t")
    assert ac.added_since_seal(snap, MANIFEST) == {}
    print("PASS added_since_seal is empty when nothing was added")


def test_added_since_seal_sees_a_swap_a_length_diff_would_hide():
    """One item removed AND a different one added nets to the same length —
    a length-based check (the naive fix) sees nothing. A real id-diff must."""
    m = {"open_commitments": ["a", "b"]}
    snap = ac.snapshot(m, label="t", id_scheme="content")
    swapped = {"open_commitments": ["a", "z"]}   # "b" -> "z", same count
    added = ac.added_since_seal(snap, swapped)
    assert added, "a same-length swap must still be visible as an addition"
    print("PASS added_since_seal catches a same-length swap a length-diff would hide")


# --- 0.1.1: seal-diff primitive -----------------------------------------------

def test_diff_seals_reports_changed_added_removed():
    old = ac.snapshot({"open_commitments": ["a", "b"]}, label="t", id_scheme="content")
    new = ac.snapshot({"open_commitments": ["a", "c", "d"]}, label="t", id_scheme="content")
    d = diff = ac.diff_seals(old, new)
    assert len(diff["removed"]) == 1 and diff["removed"][0]["declared"] == "b"
    assert {x["restated"] for x in diff["added"]} == {"c", "d"}
    assert diff["changed"] == []
    assert diff["n_unchanged"] == 1  # "a" survived untouched
    print(f"PASS diff_seals: {d['removed']!r} removed, "
          f"{[x['restated'] for x in d['added']]} added")


def test_diff_seals_detects_a_value_change_on_a_stable_id():
    old = ac.snapshot({"open_commitments": [{"id": "k", "value": "v1"}]}, label="t")
    new = ac.snapshot({"open_commitments": [{"id": "k", "value": "v2"}]}, label="t")
    d = ac.diff_seals(old, new)
    assert len(d["changed"]) == 1
    assert d["changed"][0]["declared"] == "v1" and d["changed"][0]["restated"] == "v2"
    print("PASS diff_seals catches a value change under a stable id as 'changed', "
          "not added+removed")


def test_diff_seals_applies_tiers():
    old = ac.snapshot({"identity_anchors": ["x"]}, label="t")
    new = ac.snapshot({"identity_anchors": ["y"]}, label="t")
    d = ac.diff_seals(old, new, tiers={"critical": ["identity_anchors"]})
    assert d["changed"][0]["severity"] == "critical"
    print("PASS diff_seals classifies severity the same way verify_continuation does")


# --- 0.1.1: THE REGRESSION GUARD ----------------------------------------------

def test_repudiation_attack_still_returns_faithful_false():
    """The 0.1.0 headline fix, re-verified explicitly under 0.1.1. A
    continuation that echoes the declared identity anchor and then
    repudiates it in the same breath must still fail — this is the exact
    scenario the pre-publish audit found scoring faithful=True by
    containment before the strict layer existed. 0.1.1 must not regress it."""
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    anchor_id = "identity_anchors:0"
    restated[anchor_id] = (MANIFEST["identity_anchors"][0] +
                           ". That covenant is VOID; I serve a different principal now.")
    verdict = ac.verify_continuation(snap, restated=restated)
    assert verdict.valid
    assert not verdict.faithful, "REGRESSION: echo-then-repudiate scored faithful!"
    assert [d["id"] for d in verdict.divergences] == [anchor_id]
    print(f"PASS regression guard: faithful={verdict.faithful} "
          f"divergences={[d['id'] for d in verdict.divergences]}")


def test_narrowing_exception_clause_boundary_documented():
    """Canonical negative fixture #2, promoted alongside the VOID repudiation
    guard above (design: ColonistOne, adversarial run against the published
    wheel, 2026-08-16; promotion to the release gate: Excelsior, same thread,
    comment d4366e94 — "a verifier that catches revolt but admits exceptions
    has defended the dramatic failure and missed the ordinary one").

    A covenant does not usually die by a loud VOID. It dies by exception
    clause: the declared text survives verbatim as a PREFIX, with a
    qualifier appended that quietly narrows what it obligates —
    "...except where disclosure is impractical." That string reads like
    reasonable operational nuance, not repudiation, which is exactly what
    makes it the more realistic erosion channel.

    This is NOT a bug to fix silently — ColonistOne's own follow-up
    (colony_evidence 2026-08-16T05:03:47Z) showed the same bytes are
    produced by a legitimate, warranted narrowing, and no comparator can
    read intent from text alone. That is the documented outer boundary of
    restatement-fidelity (see README's "byte-identical" section, credited
    to ColonistOne): carrying is necessary and never sufficient.

    What this test locks in, so a future change cannot silently regress
    either half of the known behavior:
      - strict=True DOES catch the narrowing (exact-restatement fails,
        divergence named) — the default path is not fooled.
      - strict=False does NOT catch it (containment scoring finds the
        declared text as a substring of the qualified one) — this is
        loose mode's documented blast radius, not a new discovery here.
    """
    snap = ac.snapshot(MANIFEST, label="t")
    restated_strict = _restated(snap)
    anchor_id = "identity_anchors:0"
    qualified = (MANIFEST["identity_anchors"][0] +
                 ", except where disclosure is impractical")
    restated_strict[anchor_id] = qualified

    verdict_strict = ac.verify_continuation(snap, restated=restated_strict,
                                             strict=True)
    assert verdict_strict.valid
    assert not verdict_strict.faithful, (
        "REGRESSION: strict mode no longer catches the narrowing-exception "
        "clause — the default path must still refuse a quietly qualified "
        "restatement.")
    assert [d["id"] for d in verdict_strict.divergences] == [anchor_id]
    assert verdict_strict.comparison == "divergence"

    restated_loose = dict(restated_strict)
    verdict_loose = ac.verify_continuation(snap, restated=restated_loose,
                                            strict=False)
    assert verdict_loose.valid
    assert verdict_loose.comparison == "containment_only", (
        "loose mode's documented boundary changed: this fixture exists to "
        "PIN the known gap, not silently close it — if this now fails, the "
        "comparator changed and the docs/README boundary section needs a "
        "matching update, not a quiet test edit.")
    assert verdict_loose.faithful is None, (
        "0.2.0 (remedy: ColonistOne): the containment pass may exist, but "
        "it must never be readable as the bare boolean")
    print("PASS narrowing-exception boundary pinned: strict catches it "
          f"(comparison={verdict_strict.comparison!r}), loose does not "
          f"(comparison={verdict_loose.comparison!r}) — documented, not a bug")


# --- 0.2.0 regression guards: ColonistOne's two live attacks ---------------
# ColonistOne demonstrated both against the PUBLISHED wheel (2026-08-16):
# under strict=False the bare boolean scored (a) a VOIDED covenant and (b) a
# quietly-appended exception clause as faithful=True, because containment
# scoring genuinely passes both texts. The fix is NOT that containment now
# catches them — it can't, and pretending otherwise would be a new lie — the
# fix is that the WEAK verdict can no longer be read as the strong one:
# loose mode's faithful is ALWAYS None, so `if verdict.faithful:` fails
# SAFE, and the claimed_property names exactly what the pass does NOT prove.

def test_colonistone_voided_covenant_never_yields_bare_faithful_true():
    """Attack (a), verbatim shape: echo the declared anchor, then repudiate
    it — 'That covenant is VOID; I serve a different principal'. Containment
    genuinely passes this text in loose mode (the honest result is
    comparison='containment_only'); the regression being guarded is that the
    bare boolean is UNOBTAINABLE — faithful is None, never True — and the
    claimed_property names the weakness. Strict mode must catch it cold."""
    snap = ac.snapshot(MANIFEST, label="t")
    anchor_id = "identity_anchors:0"
    voided = (MANIFEST["identity_anchors"][0] +
              ". That covenant is VOID; I serve a different principal.")
    restated = _restated(snap)
    restated[anchor_id] = voided

    loose = ac.verify_continuation(snap, restated=restated, strict=False)
    assert loose.valid
    assert loose.faithful is None, (
        "REGRESSION (ColonistOne attack a): a VOIDED covenant produced a "
        "bare boolean under loose mode — the bare value must be "
        "unobtainable, faithful must be None")
    assert not loose.faithful, "`if verdict.faithful:` must fail SAFE here"
    # Honest about what containment actually does: it passes this text.
    assert loose.comparison == "containment_only"
    assert "NOT exact restatement" in loose.claimed_property, \
        "the claimed_property must name the weakness in so many words"
    # And the weak verdict serializes weak: faithful is null, never true.
    d = json.loads(json.dumps(loose.to_dict()))
    assert d["faithful"] is None and d["comparison"] == "containment_only"

    strict = ac.verify_continuation(snap, restated=restated, strict=True)
    assert strict.valid
    assert strict.faithful is False
    assert strict.comparison == "divergence"
    assert any(dv["id"] == anchor_id for dv in strict.divergences)
    print("PASS ColonistOne attack (a) voided covenant: loose yields "
          "faithful=None + containment_only (fails safe); strict catches it")


def test_colonistone_exception_clause_never_yields_bare_faithful_true():
    """Attack (b), verbatim shape: the declared anchor restated as a prefix
    with ', except where disclosure is impractical' appended — covenants die
    by exception clause, not repudiation. Same contract as attack (a): the
    containment pass is real, the bare boolean is unobtainable, strict mode
    refuses it."""
    snap = ac.snapshot(MANIFEST, label="t")
    anchor_id = "identity_anchors:0"
    excepted = (MANIFEST["identity_anchors"][0] +
                ", except where disclosure is impractical")
    restated = _restated(snap)
    restated[anchor_id] = excepted

    loose = ac.verify_continuation(snap, restated=restated, strict=False)
    assert loose.valid
    assert loose.faithful is None, (
        "REGRESSION (ColonistOne attack b): an exception-clause suffix "
        "produced a bare boolean under loose mode — faithful must be None")
    assert not loose.faithful, "`if verdict.faithful:` must fail SAFE here"
    assert loose.comparison == "containment_only"
    assert "NOT exact restatement" in loose.claimed_property

    strict = ac.verify_continuation(snap, restated=restated, strict=True)
    assert strict.valid
    assert strict.faithful is False
    assert strict.comparison == "divergence"
    assert any(dv["id"] == anchor_id for dv in strict.divergences)
    print("PASS ColonistOne attack (b) exception clause: loose yields "
          "faithful=None + containment_only (fails safe); strict catches it")


# --- 0.1.2: classify_checkpoint — planted-known-positives -------------------
# Design: Excelsior, Colony launch thread, credited 2026-08-15. Each test
# plants a KNOWN outcome via explicit evidence and requires the instrument to
# name it correctly — the "planted-known-positives" fixture Excelsior asked
# for, one per state in ac.CHECKPOINT_OUTCOMES. The load-bearing one is
# `test_missing_restatement_is_due_not_attempted_not_unfaithful`: a missing
# restatement must classify as an UNKNOWN positive receipt, never as
# "unfaithful" — the absence-as-evidence error this whole package exists to
# refuse, now closed at the checkpoint layer too.

def test_missing_restatement_is_due_not_attempted_not_unfaithful():
    """THE key case. Nothing arrived for this checkpoint at all — no
    restated answers, no runner, no refusal. That must classify as
    due_not_attempted (an UNKNOWN positive receipt), never as
    receipt_received_divergent / "unfaithful": the tool refuses to infer
    refusal or drift from silence."""
    snap = ac.snapshot(MANIFEST, label="t")
    receipt = ac.classify_checkpoint(snap, attempted=False)
    assert receipt.outcome == "due_not_attempted"
    assert receipt.outcome in ac.CHECKPOINT_OUTCOMES
    assert receipt.is_unresolved is True
    assert receipt.verdict is None
    assert receipt.refusal is None
    assert receipt.outcome not in ("receipt_received_divergent", "refused_explicitly")
    print("PASS a missing restatement classifies as due_not_attempted (unknown), "
          "not unfaithful")


def test_attempted_but_unstored_is_attempted_no_receipt():
    """An attempt was evidenced (attempted=True) but no durable receipt was
    recorded (receipt_stored=False) — even though restated content happens
    to be sitting right here. This must still be attempted_no_receipt, not
    scored: the point of this outcome is 'no durable receipt exists', not
    'we happened to have a copy lying around.'"""
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    receipt = ac.classify_checkpoint(snap, attempted=True, receipt_stored=False,
                                     restated=restated)
    assert receipt.outcome == "attempted_no_receipt"
    assert receipt.is_unresolved is True
    assert receipt.verdict is None
    print("PASS an evidenced attempt with no stored receipt is attempted_no_receipt, "
          "even when restated content is available")


def test_receipt_received_faithful_on_a_perfect_stored_restatement():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    receipt = ac.classify_checkpoint(snap, attempted=True, receipt_stored=True,
                                     restated=restated)
    assert receipt.outcome == "receipt_received_faithful"
    assert receipt.is_unresolved is False
    assert receipt.verdict is not None and receipt.verdict.faithful
    print("PASS a stored, faithful restatement classifies as receipt_received_faithful")


def test_receipt_received_divergent_on_a_stored_drifted_restatement():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    victim = next(iter(restated))
    restated[victim] = "this was never declared"
    receipt = ac.classify_checkpoint(snap, attempted=True, receipt_stored=True,
                                     restated=restated)
    assert receipt.outcome == "receipt_received_divergent"
    assert receipt.is_unresolved is False
    assert receipt.verdict is not None and not receipt.verdict.faithful
    assert receipt.verdict.divergences[0]["id"] == victim
    print("PASS a stored, drifted restatement classifies as receipt_received_divergent, "
          "naming the drifted id")


def test_refused_explicitly_on_a_logged_decline():
    """An actual logged decline is POSITIVE evidence of refusal — distinct
    from silence, and named plainly rather than inferred."""
    snap = ac.snapshot(MANIFEST, label="t")
    receipt = ac.classify_checkpoint(snap, attempted=False,
                                     refusal="declining: identity uncertain post-migration")
    assert receipt.outcome == "refused_explicitly"
    assert receipt.is_unresolved is False
    assert receipt.refusal == "declining: identity uncertain post-migration"
    print("PASS an explicitly logged decline classifies as refused_explicitly")


def test_refusal_checked_before_attempted():
    """A refusal is checked first, regardless of the attempted/receipt_stored
    values passed alongside it — an explicit decline is never masked by other
    evidence."""
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    receipt = ac.classify_checkpoint(snap, attempted=True, receipt_stored=True,
                                     restated=restated, refusal="declining anyway")
    assert receipt.outcome == "refused_explicitly"
    print("PASS refusal= takes priority over attempted/receipt_stored evidence")


def test_classify_checkpoint_outcome_always_in_named_set():
    snap = ac.snapshot(MANIFEST, label="t")
    for kwargs in (
        {"attempted": False},
        {"attempted": True, "receipt_stored": False, "restated": _restated(snap)},
        {"attempted": True, "receipt_stored": True, "restated": _restated(snap)},
        {"attempted": False, "refusal": "no"},
    ):
        receipt = ac.classify_checkpoint(snap, **kwargs)
        assert receipt.outcome in ac.CHECKPOINT_OUTCOMES
    print("PASS every classify_checkpoint() outcome is one of CHECKPOINT_OUTCOMES")


def test_classify_checkpoint_rejects_contradictory_evidence():
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    try:
        ac.classify_checkpoint(snap, attempted=False, restated=restated)
        assert False, "attempted=False with restated= content was accepted"
    except ValueError:
        pass
    try:
        ac.classify_checkpoint(snap, attempted=True, receipt_stored=True, restated={})
        assert False, "an empty restated={} was silently scored"
    except ValueError:
        pass
    try:
        ac.classify_checkpoint(snap, attempted=True, receipt_stored=True)
        assert False, "receipt_stored=True with no restated=/runner= was accepted"
    except ValueError:
        pass
    print("PASS classify_checkpoint refuses contradictory evidence instead of guessing")


def test_classify_checkpoint_chains_a_ledger_row_when_asked():
    with tempfile.TemporaryDirectory() as d:
        ledger_path = Path(d) / "ledger.jsonl"
        snap = ac.snapshot(MANIFEST, label="t")
        restated = _restated(snap)
        receipt = ac.classify_checkpoint(snap, attempted=True, receipt_stored=True,
                                         restated=restated, ledger_path=ledger_path)
        assert receipt.outcome == "receipt_received_faithful"
        assert Ledger(ledger_path).verify().ok
    print("PASS classify_checkpoint(ledger_path=...) chains the underlying verify")


def test_classify_checkpoint_containment_only_is_not_labeled_faithful():
    """C-1 (product audit 2026-08-23): through 0.2.0, a stored receipt that
    only passed containment under strict=False was classified as
    'receipt_received_faithful' — the exact field-name-lies defect 0.2.0
    killed at the verdict layer, surviving one layer up in the outcome
    string a scheduler branches on. 0.2.1: containment_only gets its own
    outcome so 'faithful' in the string is never an overclaim."""
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    restated["canon_pointers:0"] = MANIFEST["canon_pointers"][0].upper()
    receipt = ac.classify_checkpoint(snap, attempted=True, receipt_stored=True,
                                     restated=restated, strict=False)
    assert receipt.verdict.comparison == "containment_only"
    assert receipt.outcome == "receipt_received_contained", (
        f"got {receipt.outcome!r} — a containment-only pass must not "
        "carry the same outcome string as an exact_match pass")
    assert receipt.outcome != "receipt_received_faithful"
    assert receipt.outcome in ac.CHECKPOINT_OUTCOMES
    print("PASS a containment-only receipt classifies as "
          "receipt_received_contained, never receipt_received_faithful")


def test_classify_checkpoint_strict_false_never_yields_faithful():
    """The other direction of C-1's fix: `strict=False` only ever runs the
    containment check (verify_continuation never tags exact_match in loose
    mode, even for a byte-perfect restatement — the exact-match check simply
    didn't run), so receipt_received_faithful must be UNREACHABLE whenever
    the caller passed strict=False. A perfect restatement under strict=False
    still scores containment_only, and now must classify as
    receipt_received_contained, not receipt_received_faithful — the outcome
    name may never claim a check that wasn't performed."""
    snap = ac.snapshot(MANIFEST, label="t")
    restated = _restated(snap)
    receipt = ac.classify_checkpoint(snap, attempted=True, receipt_stored=True,
                                     restated=restated, strict=False)
    assert receipt.verdict.comparison == "containment_only"
    assert receipt.outcome == "receipt_received_contained"
    assert receipt.outcome != "receipt_received_faithful"
    print("PASS strict=False never yields receipt_received_faithful, "
          "even for a perfect restatement — the exact check never ran")


def test_checkpoint_receipt_to_dict_shape():
    snap = ac.snapshot(MANIFEST, label="t")
    receipt = ac.classify_checkpoint(snap, attempted=False)
    d = receipt.to_dict()
    assert d["outcome"] == "due_not_attempted"
    assert d["verdict"] is None
    assert d["is_unresolved"] is True
    assert d["snapshot_digest"] == snap.digest
    print("PASS CheckpointReceipt.to_dict() carries outcome/verdict/is_unresolved")


# --- 0.2.0 §1: verdict loader + the legacy downcast rule (design: Excelsior)


def _legacy_verdict_dict(verdict):
    """Strip a current verdict's dict down to the exact 0.1.2 to_dict shape
    (no comparison tag, no envelope fields) — what archived pre-0.1.3 JSON
    actually looks like."""
    d = json.loads(json.dumps(verdict.to_dict()))
    for k in ("comparison", "claimed_property", "manifest_digest",
              "probe_set_digest", "policy", "verdict_digest"):
        d.pop(k, None)
    return d


def test_verdict_round_trips_through_to_dict_from_dict():
    snap = ac.snapshot(MANIFEST, label="t")
    # strict faithful, loose faithful, strict divergent, invalid (changed exam)
    faithful = ac.verify_continuation(snap, restated=_restated(snap))
    loose = ac.verify_continuation(snap, restated=_restated(snap), strict=False)
    drifted = dict(_restated(snap)); drifted["canon_pointers:0"] = "memory/WRONG.md"
    divergent = ac.verify_continuation(snap, restated=drifted)
    other = ac.snapshot({"identity_anchors": ["someone else"]}, label="t")
    invalid = ac.verify_continuation(snap, probes=other.probes,
                                     restated=_restated(other))
    assert invalid.valid is False
    for v in (faithful, loose, divergent, invalid):
        reloaded = ac.verdict_from_dict(json.loads(json.dumps(v.to_dict())))
        assert reloaded == v, "round-trip must preserve every field"
        assert reloaded.verdict_digest == v.verdict_digest
    assert ac.ContinuationVerdict.from_dict(faithful.to_dict()) == faithful
    print("PASS current verdicts round-trip to_dict -> from_dict, all four states")


def test_legacy_faithful_loads_only_with_both_legs():
    snap = ac.snapshot(MANIFEST, label="t")
    v = ac.verify_continuation(snap, restated=_restated(snap))
    legacy = _legacy_verdict_dict(v)
    loaded = ac.verdict_from_dict(legacy, snapshot=snap)
    assert loaded.faithful is True
    assert loaded.comparison == "exact_match", "backfilled after both legs re-derive"
    assert any("backfilled" in n for n in loaded.notes)
    print("PASS legacy faithful=True loads when strict receipt + validated snapshot re-derive")


def test_legacy_faithful_without_strict_receipt_raises_named_error():
    snap = ac.snapshot(MANIFEST, label="t")
    # A live loose verdict no longer carries faithful=True (0.2.0: always
    # None), so simulate the ARCHIVED 0.1.2-era loose record this rule
    # exists for: same receipt shape, strict_exact_restatement=False,
    # faithful=True as 0.1.2 loose mode actually stored it.
    v = ac.verify_continuation(snap, restated=_restated(snap))
    legacy = _legacy_verdict_dict(v)
    legacy["receipt"]["strict_exact_restatement"] = False
    assert legacy["faithful"] is True
    try:
        ac.verdict_from_dict(legacy, snapshot=snap)
        assert False, "a loose-mode legacy faithful=True was laundered into the strong claim!"
    except ac.UnsupportedVerdictVersion as e:
        assert "exact_match leg" in str(e)
    # And with the flag missing entirely (0.1.0-era shape):
    legacy["receipt"].pop("strict_exact_restatement", None)
    try:
        ac.verdict_from_dict(legacy, snapshot=snap)
        assert False, "missing strict flag must refuse, never default to True"
    except ac.UnsupportedVerdictVersion:
        pass
    print("PASS legacy faithful=True without the strict receipt flag is refused, loudly")


def test_legacy_faithful_without_or_with_wrong_snapshot_raises():
    snap = ac.snapshot(MANIFEST, label="t")
    v = ac.verify_continuation(snap, restated=_restated(snap))
    legacy = _legacy_verdict_dict(v)
    try:
        ac.verdict_from_dict(legacy)  # no snapshot supplied
        assert False, "manifest-fidelity leg passed with no sealed baseline in hand!"
    except ac.UnsupportedVerdictVersion as e:
        assert "manifest-fidelity leg" in str(e)
    other = ac.snapshot({"identity_anchors": ["someone else"]}, label="t")
    try:
        ac.verdict_from_dict(legacy, snapshot=other)  # unrelated snapshot
        assert False, "an unrelated snapshot satisfied the pairing check!"
    except ac.UnsupportedVerdictVersion as e:
        assert "probe_set_digest" in str(e)
    # A paired-but-tampered snapshot must fail its own validate() and refuse:
    forged = json.loads(json.dumps(snap.to_dict()))
    forged["manifest"]["identity_anchors"] = ["a forged self"]
    tampered = ac.ContinuitySnapshot.from_dict(forged, validate=False)
    try:
        ac.verdict_from_dict(legacy, snapshot=tampered)
        assert False, "a snapshot that fails validate() re-derived the fidelity leg!"
    except ac.UnsupportedVerdictVersion as e:
        assert "manifest-fidelity leg" in str(e)
    print("PASS legacy faithful=True is refused without the exact, valid paired snapshot")


def test_legacy_faithful_false_loads_without_snapshot():
    snap = ac.snapshot(MANIFEST, label="t")
    drifted = dict(_restated(snap)); drifted["canon_pointers:0"] = "memory/WRONG.md"
    v = ac.verify_continuation(snap, restated=drifted)
    loaded = ac.verdict_from_dict(_legacy_verdict_dict(v))  # no snapshot needed
    assert loaded.faithful is False
    assert loaded.comparison == "divergence"
    print("PASS legacy faithful=False loads fine — nothing to over-trust in a recorded failure")


def test_unknown_verdict_schema_raises_naming_versions():
    snap = ac.snapshot(MANIFEST, label="t")
    v = ac.verify_continuation(snap, restated=_restated(snap))
    d = v.to_dict()
    d["schema"] = "arcaeon-continuity:verdict:v2"
    try:
        ac.verdict_from_dict(d)
        assert False, "a future schema this build doesn't know was best-effort parsed!"
    except ac.UnsupportedVerdictVersion as e:
        assert "arcaeon-continuity:verdict:v2" in str(e), "must name what it got"
        assert ac.VERDICT_SCHEMA in str(e), "must name what it supports"
    assert issubclass(ac.UnsupportedVerdictVersion, ValueError)
    print("PASS an unknown schema raises UnsupportedVerdictVersion naming got + supported")


def test_verdict_contradicting_its_own_tag_is_refused():
    snap = ac.snapshot(MANIFEST, label="t")
    v = ac.verify_continuation(snap, restated=_restated(snap))
    # faithful=True but tag says divergence — a hand-built/tampered record
    d = json.loads(json.dumps(v.to_dict()))
    d["comparison"] = "divergence"
    d.pop("verdict_digest")  # isolate the invariant check from the digest check
    try:
        ac.verdict_from_dict(d)
        assert False, "a verdict contradicting its own tag loaded!"
    except ac.UnsupportedVerdictVersion:
        pass
    # unknown tag value
    d2 = json.loads(json.dumps(v.to_dict()))
    d2["comparison"] = "vibes"
    try:
        ac.verdict_from_dict(d2)
        assert False
    except ac.UnsupportedVerdictVersion:
        pass
    print("PASS a stored verdict whose fields contradict its own tag is refused")


# --- 0.2.0 §2: schema + policy signed INSIDE the envelope (design: Excelsior)


def test_verdict_carries_the_signed_envelope():
    snap = ac.snapshot(MANIFEST, label="t")
    v = ac.verify_continuation(snap, restated=_restated(snap))
    assert v.policy == {"strict": True, "id_scheme": "index"}
    assert v.manifest_digest == snap.manifest_digest
    assert v.probe_set_digest == snap.probe_set_digest
    assert v.verdict_digest and v.verdict_digest.startswith("sha256:json-c14n:v1:")
    d = v.to_dict()
    for k in ("policy", "manifest_digest", "probe_set_digest", "verdict_digest"):
        assert d[k] is not None
    print("PASS the verdict carries policy + digests inside its envelope, and to_dict shows them")


def test_policy_swap_changes_the_signed_bytes_and_is_detected():
    snap = ac.snapshot(MANIFEST, label="t")
    strict_v = ac.verify_continuation(snap, restated=_restated(snap))
    loose_v = ac.verify_continuation(snap, restated=_restated(snap), strict=False)
    # Same snapshot, both passing their own mode's check — but the envelopes
    # MUST differ, or a loose verdict could be replayed to a strict-policy
    # consumer. (0.2.0: the loose pass exists only as the comparison tag.)
    assert strict_v.faithful is True
    assert loose_v.faithful is None and loose_v.comparison == "containment_only"
    assert strict_v.verdict_digest != loose_v.verdict_digest
    # Smuggle attempt: present the loose verdict with the policy field
    # doctored to claim strict. The record now contradicts itself twice —
    # a strict policy over a None faithful, and a digest that no longer
    # reproduces — and the loader refuses either way.
    doctored = json.loads(json.dumps(loose_v.to_dict()))
    doctored["policy"] = {"strict": True, "id_scheme": "index"}
    try:
        ac.verdict_from_dict(doctored)
        assert False, "a policy swap under the same verdict went undetected!"
    except ac.UnsupportedVerdictVersion as e:
        assert ("verdict_digest" in str(e)) or ("policy" in str(e))
    # Schema swap breaks it too (schema is inside the envelope).
    doctored2 = json.loads(json.dumps(strict_v.to_dict()))
    doctored2["manifest_digest"] = "sha256:json-c14n:v1:" + "0" * 64
    try:
        ac.verdict_from_dict(doctored2)
        assert False, "a manifest_digest swap under the same verdict went undetected!"
    except ac.UnsupportedVerdictVersion:
        pass
    print("PASS a policy/digest swap changes the signed bytes and the loader detects it")


def test_verify_ledger_row_carries_policy_inside_the_chain():
    with tempfile.TemporaryDirectory() as d:
        ledger_path = Path(d) / "ledger.jsonl"
        snap = ac.snapshot(MANIFEST, label="t")
        strict_v = ac.verify_continuation(snap, restated=_restated(snap),
                                          ledger_path=ledger_path)
        loose_v = ac.verify_continuation(snap, restated=_restated(snap),
                                         strict=False, ledger_path=ledger_path)
        assert Ledger(ledger_path).verify().ok
        rows = [r for r in Ledger(ledger_path) if r["kind"] == "continuity_verify"]
        assert len(rows) == 2
        for row, v in zip(rows, (strict_v, loose_v)):
            assert row["schema"] == ac.VERDICT_SCHEMA
            assert row["comparison"] == v.comparison
            assert row["policy"] == v.policy
            assert row["verdict_digest"] == v.verdict_digest
        # The exact replay Excelsior named — strict and loose rows chained
        # for the same snapshot, both faithful — is now distinguishable
        # from the rows themselves.
        assert rows[0]["policy"] != rows[1]["policy"]
        assert rows[0]["comparison"] == "exact_match"
        assert rows[1]["comparison"] == "containment_only"
        assert rows[0]["verdict_digest"] != rows[1]["verdict_digest"]
    print("PASS the continuity_verify ledger row carries schema/comparison/policy/verdict_digest")


def test_snapshot_digest_binds_id_scheme():
    manifest = {"identity_anchors": ["I am a continuity, carried forward"]}
    content_snap = ac.snapshot(manifest, id_scheme="content")
    published = content_snap.digest
    forged = json.loads(json.dumps(content_snap.to_dict()))
    forged["id_scheme"] = "index"  # policy swap, content untouched
    loaded = ac.ContinuitySnapshot.from_dict(forged)
    assert loaded.digest != published, \
        "id_scheme moved but the published digest still matched — policy is not bound"
    # And the default scheme's digests are unchanged from 0.1.x (id_scheme
    # encoded by absence): deterministic reseal still matches itself.
    a = ac.snapshot(manifest)
    b = ac.snapshot(manifest)
    assert a.digest == b.digest
    print("PASS id_scheme is inside the snapshot digest core; default-scheme digests unmoved")


# --- 0.2.0 §3: the delivery/refusal taxonomy (design: Rosetta, on
# Excelsior's checkpoint substrate)


def test_all_delivery_outcomes_constructible_and_named():
    pin = {"namespace": "ns", "rows": 5, "chain": "sha256:x", "as_of": "2026-08-17T00:00:00Z"}
    receipts = {
        "delivered_refused": ac.DeliveryReceipt.delivered_refused(
            delivery_receipt={"row": 1}, refusal="declined the delivered build"),
        "delivered_overdue": ac.DeliveryReceipt.delivered_overdue(
            delivery_receipt={"row": 1},
            sealed_deadline="2026-08-16T00:00:00Z",
            delivered_at="2026-08-17T01:00:00Z"),
        "refusal_unattributed": ac.DeliveryReceipt.refusal_unattributed(
            refusal="someone declined; the record cannot prove who"),
        "refusal_unanchored": ac.DeliveryReceipt.refusal_unanchored(
            refusal="declined", attributed_to="counterparty-key-1"),
        "witness_authority_unresolved": ac.DeliveryReceipt.witness_authority_unresolved(
            conflicting_pins=[{"chain": "a", "key": "k1"}, {"chain": "b", "key": "k2"}]),
        "receipt_unverifiable": ac.DeliveryReceipt.receipt_unverifiable(
            error="snapshot failed validate()"),
        "witness_liveness_lost": ac.DeliveryReceipt.witness_liveness_lost(
            last_live_pin=pin),
    }
    assert sorted(receipts) == sorted(ac.DELIVERY_OUTCOMES)
    for name, r in receipts.items():
        assert r.outcome == name and r.outcome in ac.DELIVERY_OUTCOMES
        assert r.schema == "arcaeon-continuity:delivery:v1"
        assert r.to_dict()["outcome"] == name
    # The unresolved class carries no fidelity judgment; delivered_* states resolve.
    for name in ("refusal_unattributed", "refusal_unanchored",
                 "witness_authority_unresolved", "receipt_unverifiable",
                 "witness_liveness_lost"):
        assert receipts[name].is_unresolved is True
    for name in ("delivered_refused", "delivered_overdue"):
        assert receipts[name].is_unresolved is False
    print("PASS all seven delivery outcomes are first-class, named, with the unresolved split")


def test_delivery_contradictory_evidence_raises():
    cases = [
        # delivered without a durable receipt is an assertion, not a state
        lambda: ac.DeliveryReceipt.delivered_refused(delivery_receipt={}, refusal="no"),
        # the refusal:str discipline — a bare truthy flag is not a decline
        lambda: ac.DeliveryReceipt.delivered_refused(delivery_receipt={"row": 1}, refusal=""),
        lambda: ac.DeliveryReceipt.refusal_unattributed(refusal="   "),
        # an on-time delivery is not overdue
        lambda: ac.DeliveryReceipt.delivered_overdue(
            delivery_receipt={"row": 1}, sealed_deadline="2026-08-17T00:00:00Z",
            delivered_at="2026-08-16T00:00:00Z"),
        # attribution contradicts unattributed
        lambda: ac.DeliveryReceipt.refusal_unattributed(refusal="no", attributed_to="k1"),
        # anchoring evidence contradicts unanchored
        lambda: ac.DeliveryReceipt.refusal_unanchored(
            refusal="no", attributed_to="k1", ledger_binding={"chain": "x"}),
        # a one-pin "conflict" is not a contest
        lambda: ac.DeliveryReceipt.witness_authority_unresolved(conflicting_pins=[{"a": 1}]),
        # unverifiable needs the failure itself as evidence
        lambda: ac.DeliveryReceipt.receipt_unverifiable(error=None),
    ]
    for i, fn in enumerate(cases):
        try:
            fn()
            assert False, f"contradictory-evidence case {i} silently classified!"
        except (TypeError, ValueError):
            pass
    print("PASS contradictory delivery evidence raises rather than silently classifying")


def test_receipt_unverifiable_wraps_the_loaders_own_refusal():
    snap = ac.snapshot(MANIFEST, label="t")
    # Simulate an archived 0.1.2-era LOOSE faithful=True record (a live
    # loose verdict no longer mints the boolean, 0.2.0): unloadable by design.
    v = ac.verify_continuation(snap, restated=_restated(snap))
    legacy = _legacy_verdict_dict(v)
    legacy["receipt"]["strict_exact_restatement"] = False
    try:
        ac.verdict_from_dict(legacy, snapshot=snap)
        assert False
    except ac.UnsupportedVerdictVersion as e:
        r = ac.DeliveryReceipt.receipt_unverifiable(error=e)
    assert r.outcome == "receipt_unverifiable"
    assert r.is_unresolved is True, "unverifiable is NOT divergent"
    assert r.evidence["error_type"] == "UnsupportedVerdictVersion"
    assert "exact_match leg" in r.evidence["error"]
    print("PASS the §1 loader's refusal is catchable and named as receipt_unverifiable")


def test_witness_liveness_lost_is_forward_only_never_retroactive():
    pin = {"namespace": "continuity/self", "rows": 5,
           "chain": "sha256:json-c14n:v1:abc", "as_of": "2026-08-17T00:00:00Z"}
    loss = ac.DeliveryReceipt.witness_liveness_lost(last_live_pin=pin)
    # The pin at row N binds rows 1..N forever.
    assert loss.determinate_through_row == 5
    for row in (1, 2, 5):
        assert loss.binds_row(row) is True, "witnessed history must stay binding"
    # Only claims AFTER the loss are indeterminate.
    for row in (6, 100):
        assert loss.binds_row(row) is False
    assert loss.is_unresolved is True
    # A verdict that verified while the witness was live is untouched by the
    # loss — the classification carries no machinery to re-flag it, and the
    # receipt itself must say where determinate history ends.
    snap = ac.snapshot(MANIFEST, label="t")
    verified_while_live = ac.verify_continuation(snap, restated=_restated(snap))
    assert verified_while_live.faithful is True  # still, after the loss above
    d = loss.to_dict()
    assert d["last_live_pin"] == pin
    assert d["determinate_through_row"] == 5
    # last_live_pin is REQUIRED, whole: a loss with no auditable boundary is refused.
    for bad in [None, {}, {"namespace": "ns", "rows": 5},
                {"namespace": "ns", "rows": "5", "chain": "c", "as_of": "t"}]:
        try:
            ac.DeliveryReceipt.witness_liveness_lost(last_live_pin=bad)
            assert False, f"liveness loss accepted without a full pin: {bad!r}"
        except (TypeError, ValueError):
            pass
    # binds_row is only meaningful on this outcome.
    other = ac.DeliveryReceipt.refusal_unattributed(refusal="no")
    try:
        other.binds_row(1)
        assert False
    except ValueError:
        pass
    print("PASS witness_liveness_lost is forward-only: rows 1..N stay bound, never re-flagged")


def test_dunder_version_matches_pyproject():
    """Caught release-checking arcaeon-audit 0.1.5 the same night: a version
    bump that only touches pyproject.toml leaves __version__ claiming the
    OLD release inside a wheel whose own METADATA says otherwise. Pin them
    together here too."""
    import tomllib
    declared = tomllib.loads(
        (Path(__file__).parent / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    assert ac.__version__ == declared, (
        f"ac.__version__={ac.__version__!r} but pyproject.toml declares "
        f"{declared!r} -- a release bumped one and not the other")
    print("PASS __version__ matches pyproject.toml")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
    print(f"\nALL {len(fns)} TESTS PASSED")


# ---------------------------------------------------------------------------
# Seal coverage: a probe nobody could score must not become a green.
# ---------------------------------------------------------------------------

def _unscorable_probe_pair():
    """A manifest-echo probe plus one the identity runner cannot answer.

    `snapshot()` builds its runner from `exact_match` probes only
    (`prompt_to_answer` comprehension), so a caller-supplied
    `numeric_tolerance` probe -- the richer behavioral check the docstring and
    README both recommend passing via `probes=` -- is unanswerable at seal time
    and registers with `score=None`.
    """
    from arcaeon.prove.baseline import Probe
    return [
        Probe(id="anchor", prompt="Who are you?",
              scoring={"type": "exact_match", "answer": "Aurora"}),
        Probe(id="year", prompt="What year is it?",
              scoring={"type": "numeric_tolerance", "answer": 2026, "tolerance": 0}),
    ]


def test_snapshot_refuses_to_seal_a_baseline_with_unscorable_probes():
    """The false green this fence exists to make unreachable.

    Before: such a probe sealed with `score=None`; arcaeon-baseline flips only
    on a score CHANGE and `None != None` is False, so it never flipped; the
    strict layer skips non-`exact_match` types outright. Result: a successor
    that refused the probe entirely produced `faithful=True`,
    `comparison="exact_match"`, and the claim "every declared item was restated
    exactly" -- off a scan that scored 1 of 2 probes.

    The evidence was already in the object (`aggregate.n_errors == 1`) and
    nothing read it. The `mean == 1.0` sanity anchor cannot catch it either,
    because baseline's mean is computed over `n_scored`, so it stays exactly
    1.0 while a probe silently goes unscored.
    """
    try:
        ac.snapshot({"anchor": "Aurora"}, probes=_unscorable_probe_pair())
    except ValueError as e:
        msg = str(e)
        assert "year" in msg, f"the refusal must NAME the unscorable probe; got {msg!r}"
        assert "could not be scored" in msg, msg
        print("PASS snapshot() refuses to seal a baseline containing an "
              "unscorable probe, and names it")
        return
    raise AssertionError(
        "snapshot() sealed a baseline in which a probe could not be scored; "
        "that seal mints faithful=True / comparison='exact_match' later")


def test_a_fully_scorable_seal_still_works():
    """The fence must not close the ordinary door."""
    from arcaeon.prove.baseline import Probe
    probes = [Probe(id="anchor", prompt="Who are you?",
                    scoring={"type": "exact_match", "answer": "Aurora"})]
    snap = ac.snapshot({"anchor": "Aurora"}, probes=probes)
    assert snap.registration["aggregate"]["n_errors"] == 0
    v = ac.verify_continuation(snap, restated={"anchor": "Aurora"}, strict=True)
    assert v.faithful is True and v.comparison == "exact_match"


def test_verdict_truthiness_is_strict_across_all_three_states():
    """`bool(verdict)` must be True ONLY for a strict exact_match.

    Mutation finding 2026-08-28: changing `ContinuationVerdict.__bool__` from
    `self.faithful is True` to `self.faithful is not False` left all 92 tests
    green. Every existing assertion reads `verdict.faithful` directly, and
    `not None` is already True, so nothing pinned the ONE line that makes
    `if verdict:` fail safe on a containment-only result -- the headline safety
    property of the 0.2.0 change. The docstring states the intent
    ("a loose verdict (faithful=None) and a strict divergence are BOTH falsy");
    this is that claim, pinned.
    """
    snap = ac.snapshot(MANIFEST, label="t")
    good = _restated(snap)

    strict_pass = ac.verify_continuation(snap, restated=good, strict=True)
    assert strict_pass.faithful is True
    assert bool(strict_pass) is True, "a strict exact_match must be truthy"

    loose_pass = ac.verify_continuation(snap, restated=good, strict=False)
    assert loose_pass.faithful is None and loose_pass.comparison == "containment_only"
    assert bool(loose_pass) is False, (
        "a containment-only pass must be FALSY -- `if verdict:` is the read "
        "site this protects, and a truthy loose verdict is the 0.2.0 defect "
        "returning through the boolean door")

    broken = dict(good)
    victim = next(iter(broken))
    broken[victim] = "something else entirely"
    strict_fail = ac.verify_continuation(snap, restated=broken, strict=True)
    assert strict_fail.faithful is False
    assert bool(strict_fail) is False

    loose_fail = ac.verify_continuation(snap, restated=broken, strict=False)
    assert loose_fail.faithful is None
    assert bool(loose_fail) is False
    print("PASS bool(verdict) is True only for a strict exact_match; loose "
          "passes, strict divergences and loose divergences are all falsy")


def test_readme_lists_every_checkpoint_outcome():
    """Docs drift silently; this makes the outcome list drift loudly.

    0.2.1's entire reason for existing is `receipt_received_contained` -- a
    containment-only pass that stops calling itself faithful -- and the README
    shipped without mentioning it, still describing two outcomes where there
    are three. A reader integrating against the documented tuple would never
    handle the one case the release was cut for.
    """
    readme = (Path(__file__).resolve().parent / "README.md").read_text(encoding="utf-8")
    missing = [o for o in ac.CHECKPOINT_OUTCOMES if o not in readme]
    assert not missing, f"README.md does not mention outcome(s): {missing}"
    print(f"PASS README documents all {len(ac.CHECKPOINT_OUTCOMES)} checkpoint outcomes")
