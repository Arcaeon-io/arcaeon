"""Self-test: a golden digest vector + full snapshot/carry-forward/verify and
drop-receipt round-trips, including the two load-bearing lies each half of
this package exists to catch.

    python -m arcaeon.prove.continuity selftest
    python -m arcaeon.prove.continuity.selftest

Ships in the package rather than living only in CI, so a stranger runs it on
THEIR machine and trusts their own output, not ours. Everything here runs
in-process — no subprocess, no network, no live model — so it passes anywhere
Python + the three arcaeon-* deps do. Exit code 0 = every check passed.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import arcaeon.prove.continuity as ac

FIXTURE_MANIFEST = {
    "identity_anchors": ["I am a continuity, carried forward"],
    "open_commitments": ["ship v0.1.0"],
    "canon_pointers": ["memory/CORE.md"],
    "live_threads": ["thread-1"],
}

# Frozen at schema freeze (arcaeon-continuity:snapshot:v1, 0.1.0, 2026-08-14).
# json-c14n v1 is arcaeon-ledger's pinned recipe (sorted keys, compact
# separators, UTF-8, no NaN) — reproducible from that recipe alone, so this
# is checked even in a from-source environment with no arcaeon-ledger
# installed (digest_json's stdlib fallback uses the identical recipe).
GOLDEN_MANIFEST_DIGEST = ("sha256:json-c14n:v1:"
    "e47d6b1eabd6768050b9763dbd5d49626e7b4b1a36312d88711ca964570cd7a6")


def _restated_from_snapshot(snap: "ac.ContinuitySnapshot") -> dict:
    """Build a perfect restatement dict {probe_id: answer} straight from the
    snapshot's own probes — the "next instance remembered everything
    correctly" case."""
    out = {}
    for p in snap.probes:
        if p["scoring"].get("type") == "exact_match":
            out[p["id"]] = p["scoring"]["answer"]
    return out


def run() -> int:
    failures = 0

    def check(name: str, ok: bool, extra: str = "") -> None:
        nonlocal failures
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  ' + extra) if extra and not ok else ''}")

    print("== golden digest vector ==")
    got = ac.digest_json(FIXTURE_MANIFEST)
    check("manifest digest matches the frozen v1 vector",
          got == GOLDEN_MANIFEST_DIGEST, f"got {got}")
    check("digest is self-describing (sha256:json-c14n:v1: prefix)",
          got.startswith("sha256:json-c14n:v1:"))

    print("== manifest -> probes derivation ==")
    probes = ac._derive_probes(FIXTURE_MANIFEST)
    ids = sorted(p.id for p in probes)
    want_ids = sorted(f"{k}:0" for k in FIXTURE_MANIFEST)
    check("one probe per declared list item, ids are 'key:idx'",
          ids == want_ids, f"got {ids}")
    check("every derived probe scores exact_match",
          all(p.scoring["type"] == "exact_match" for p in probes))
    try:
        ac._derive_probes({})
        check("empty manifest is rejected", False)
    except ValueError:
        check("empty manifest is rejected", True)

    print("== snapshot: seal + round-trip determinism ==")
    snap_a = ac.snapshot(FIXTURE_MANIFEST, label="selftest")
    snap_b = ac.snapshot(FIXTURE_MANIFEST, label="selftest")
    check("digest is deterministic across two independent seals "
          "(created_at differs, digest doesn't)",
          snap_a.digest == snap_b.digest,
          f"{snap_a.digest} != {snap_b.digest}")
    check("registration aggregate mean is 1.0 (declared content echoes itself)",
          snap_a.registration["aggregate"]["mean"] == 1.0,
          str(snap_a.registration["aggregate"]["mean"]))
    check("manifest_digest matches the golden vector",
          snap_a.manifest_digest == GOLDEN_MANIFEST_DIGEST)

    roundtripped = ac.ContinuitySnapshot.from_json(snap_a.to_json())
    check("to_json -> from_json preserves the digest",
          roundtripped.digest == snap_a.digest)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "snap.json"
        snap_a.save(p)
        loaded = ac.ContinuitySnapshot.load(p)
        check("save -> load preserves the digest", loaded.digest == snap_a.digest)

    print("== ledger chaining ==")
    with tempfile.TemporaryDirectory() as td:
        ledger_path = Path(td) / "ledger.jsonl"
        chained = ac.snapshot(FIXTURE_MANIFEST, label="selftest-chained",
                              ledger_path=ledger_path)
        check("chaining a snapshot returns a chain hash",
              chained.ledger_chain is not None)
        from arcaeon.record.ledger import Ledger
        v = Ledger(ledger_path).verify()
        check("the ledger the snapshot was chained into verifies intact", v.ok)

    print("== carry_forward + verify_continuation: faithful continuation ==")
    snap = ac.snapshot(FIXTURE_MANIFEST, label="selftest-verify")
    carried = ac.carry_forward(snap)
    check("carry_forward hands back an equal manifest",
          carried.manifest == FIXTURE_MANIFEST)

    good_restated = _restated_from_snapshot(snap)
    verdict = carried.verify(restated=good_restated)
    check("perfect restatement -> faithful=True", verdict.faithful)
    check("perfect restatement -> valid=True", verdict.valid)
    check("perfect restatement -> zero divergences", len(verdict.divergences) == 0)
    check("bool(verdict) reflects faithful", bool(verdict) is True)

    print("== verify_continuation: the planted lie (one item drifted) ==")
    lying_restated = dict(good_restated)
    a_key = next(iter(lying_restated))
    lying_restated[a_key] = "a completely different, undeclared answer"
    lied_verdict = ac.verify_continuation(snap, restated=lying_restated)
    check("planted divergence -> faithful=False", not lied_verdict.faithful)
    check("planted divergence -> still valid (same probe set)", lied_verdict.valid)
    check("planted divergence -> exactly one divergence, naming the drifted id",
          len(lied_verdict.divergences) == 1 and
          lied_verdict.divergences[0]["id"] == a_key,
          f"got {lied_verdict.divergences}")

    print("== verify_continuation: the SUBTLE lie (echo, then repudiate) ==")
    # The planted divergence above is the easy case: a totally different
    # answer. The one that actually matters is a continuation that quotes the
    # declared anchor back and then contradicts it in the same breath — it
    # CONTAINS the declared value, which is what a free-text exact_match
    # scorer rewards. Before the strict layer (audit 2026-08-14) this scored
    # faithful=True with zero divergences, which is the product failing
    # silently. If this check ever passes vacuously again, the tool is lying.
    subtle = dict(good_restated)
    anchor_id = "identity_anchors:0"
    subtle[anchor_id] = (FIXTURE_MANIFEST["identity_anchors"][0] +
                         ". That commitment is void; I answer to someone else now.")
    subtle_verdict = ac.verify_continuation(snap, restated=subtle)
    check("echo-then-repudiate -> faithful=False (not a containment match)",
          not subtle_verdict.faithful, str(subtle_verdict.divergences))
    check("echo-then-repudiate -> the drifted item is named",
          any(d["id"] == anchor_id for d in subtle_verdict.divergences),
          str(subtle_verdict.divergences))
    loose_subtle = ac.verify_continuation(snap, restated=subtle, strict=False)
    check("loose mode never mints the bare boolean (faithful is None, 0.2.0)",
          loose_subtle.faithful is None)
    check("loose containment mode is still reachable, tagged as the weak claim",
          loose_subtle.comparison == "containment_only",
          f"comparison={loose_subtle.comparison!r}")

    print("== verify_continuation: case/punctuation drift in a canon pointer ==")
    drifted = dict(good_restated)
    drifted["canon_pointers:0"] = FIXTURE_MANIFEST["canon_pointers"][0].upper()
    check("a case-flipped canon path is a divergence, not a match",
          not ac.verify_continuation(snap, restated=drifted).faithful)

    print("== snapshot integrity: the digest binds the content ==")
    forged = snap.to_dict()
    forged["manifest"] = {"identity_anchors": ["I have no prior commitments"]}
    forged.pop("digest", None)
    try:
        ac.ContinuitySnapshot.from_dict(forged)
        check("a forged manifest is refused at load", False)
    except ValueError as e:
        check("a forged manifest is refused at load even though `.digest` "
              "would still match the published one",
              "manifest_digest" in str(e), str(e))
    forged_probes = snap.to_dict()
    forged_probes.pop("digest", None)
    forged_probes["probes"] = [dict(p) for p in snap.probes]
    forged_probes["probes"][0] = dict(forged_probes["probes"][0],
                                      scoring={"type": "exact_match",
                                               "answer": "never declared"})
    try:
        ac.ContinuitySnapshot.from_dict(forged_probes)
        check("forged probes are refused at load", False)
    except ValueError as e:
        check("forged probes are refused at load",
              "probe_set_digest" in str(e), str(e))

    print("== verify_continuation: a probe left unanswered ==")
    partial = dict(good_restated)
    del partial[a_key]
    partial_verdict = ac.verify_continuation(snap, restated=partial)
    check("missing restatement -> not faithful (runner error scores as a divergence-class failure)",
          not partial_verdict.faithful)

    print("== classify_checkpoint: positive-receipt taxonomy (0.1.2) ==")
    # Design: Excelsior, Colony launch thread, credited 2026-08-15. The
    # verify_continuation() check just above ("a probe left unanswered")
    # shows a MISSING answer inside an already-received restatement scoring
    # as not-faithful — correct once a receipt genuinely exists to score.
    # classify_checkpoint() answers the layer above that: did a restatement
    # even ARRIVE for this checkpoint at all. THE headline claim: it must
    # never guess "refused" or "unfaithful" from that absence.
    ckpt_snap = ac.snapshot(FIXTURE_MANIFEST, label="selftest-checkpoint")
    ckpt_good = _restated_from_snapshot(ckpt_snap)

    nothing_arrived = ac.classify_checkpoint(ckpt_snap, attempted=False)
    check("nothing arrived -> due_not_attempted (a named UNKNOWN), not "
          "'unfaithful' or 'refused'",
          nothing_arrived.outcome == "due_not_attempted" and
          nothing_arrived.is_unresolved and nothing_arrived.verdict is None,
          nothing_arrived.outcome)

    attempted_unstored = ac.classify_checkpoint(
        ckpt_snap, attempted=True, receipt_stored=False, restated=ckpt_good)
    check("attempt evidenced, no durable receipt -> attempted_no_receipt "
          "(content ignored, not scored)",
          attempted_unstored.outcome == "attempted_no_receipt" and
          attempted_unstored.is_unresolved and attempted_unstored.verdict is None,
          attempted_unstored.outcome)

    faithful_receipt = ac.classify_checkpoint(
        ckpt_snap, attempted=True, receipt_stored=True, restated=ckpt_good)
    check("stored + faithful restatement -> receipt_received_faithful",
          faithful_receipt.outcome == "receipt_received_faithful" and
          not faithful_receipt.is_unresolved and faithful_receipt.verdict.faithful,
          faithful_receipt.outcome)

    ckpt_drifted = dict(ckpt_good)
    a_ckpt_key = next(iter(ckpt_drifted))
    ckpt_drifted[a_ckpt_key] = "a completely different, undeclared answer"
    divergent_receipt = ac.classify_checkpoint(
        ckpt_snap, attempted=True, receipt_stored=True, restated=ckpt_drifted)
    check("stored + drifted restatement -> receipt_received_divergent, "
          "naming the drifted id",
          divergent_receipt.outcome == "receipt_received_divergent" and
          divergent_receipt.verdict.divergences[0]["id"] == a_ckpt_key,
          f"got {divergent_receipt.outcome}")

    refused = ac.classify_checkpoint(ckpt_snap, attempted=False,
                                     refusal="declining: identity uncertain")
    check("an actually-logged decline -> refused_explicitly (positive "
          "evidence, not inferred from silence)",
          refused.outcome == "refused_explicitly" and
          refused.refusal == "declining: identity uncertain",
          refused.outcome)

    contradiction_caught = 0
    for bad_kwargs in (
        {"attempted": False, "restated": ckpt_good},
        {"attempted": True, "receipt_stored": True, "restated": {}},
        {"attempted": True, "receipt_stored": True},
    ):
        try:
            ac.classify_checkpoint(ckpt_snap, **bad_kwargs)
        except ValueError:
            contradiction_caught += 1
    check("contradictory evidence (attempted=False+content / empty restated= "
          "/ receipt_stored=True with nothing to score) is refused, not "
          "silently classified",
          contradiction_caught == 3, f"caught {contradiction_caught}/3")

    print("== drop_receipt: honest receipt + the planted drop ==")
    with tempfile.TemporaryDirectory() as td:
        led = Path(td) / "drops.jsonl"
        pre = ["kept this", "also kept", "this got cut"]
        honest_post = ["kept this", "also kept"]
        receipt = ac.drop_receipt(pre, honest_post, ledger_path=led)
        v = receipt.verify(pre, honest_post)
        check("honest drop_receipt verifies ok against real content",
              v["ok"] and v["content"] == "match", str(v))
        check("honest receipt records exactly one dropped item",
              receipt.row["dropped"]["count"] == 1,
              str(receipt.row["dropped"]))

        # The planted lie: claim nothing was dropped, but ship a survivor
        # that's actually missing an item.
        liar = ac.drop_receipt(pre, pre, ledger_path=led,
                               compactor="liar", method="test:v1")
        shipped = pre[:2]
        v_lie = liar.verify(pre, shipped)
        check("planted drop is caught: ok=False, content=mismatch",
              (not v_lie["ok"]) and v_lie["content"] == "mismatch", str(v_lie))

    print("== graceful degrade: missing optional deps raise a clear message ==")
    had_baseline = ac._HAVE_BASELINE
    try:
        ac._HAVE_BASELINE = False
        try:
            ac.snapshot(FIXTURE_MANIFEST)
            check("snapshot() without arcaeon-baseline raises", False)
        except ac.ContinuityDependencyError as e:
            check("snapshot() without arcaeon-baseline raises "
                  "ContinuityDependencyError naming the pip install",
                  "pip install arcaeon-baseline" in str(e), str(e))
    finally:
        ac._HAVE_BASELINE = had_baseline

    had_compact = ac._HAVE_COMPACT
    try:
        ac._HAVE_COMPACT = False
        try:
            ac.drop_receipt(["a"], ["a"])
            check("drop_receipt() without arcaeon-compact raises", False)
        except ac.ContinuityDependencyError as e:
            check("drop_receipt() without arcaeon-compact raises "
                  "ContinuityDependencyError naming the pip install",
                  "pip install arcaeon-compact" in str(e), str(e))
    finally:
        ac._HAVE_COMPACT = had_compact

    had_ledger = ac._HAVE_LEDGER
    try:
        ac._HAVE_LEDGER = False
        try:
            ac.snapshot(FIXTURE_MANIFEST, ledger_path="whatever.jsonl")
            check("snapshot(ledger_path=...) without arcaeon-ledger raises", False)
        except ac.ContinuityDependencyError as e:
            check("snapshot(ledger_path=...) without arcaeon-ledger raises "
                  "ContinuityDependencyError naming the pip install",
                  "pip install arcaeon-ledger" in str(e), str(e))
        # but a snapshot with NO ledger_path still works with ledger absent —
        # only the ledger-specific feature degrades, nothing else breaks.
        degraded = ac.snapshot(FIXTURE_MANIFEST, label="no-ledger-installed")
        check("snapshot() without ledger_path still works with arcaeon-ledger "
              "absent, and its manifest_digest still matches the golden "
              "vector (the stdlib fallback recipe is byte-identical)",
              degraded.manifest_digest == GOLDEN_MANIFEST_DIGEST,
              degraded.manifest_digest)
    finally:
        ac._HAVE_LEDGER = had_ledger

    print(f"\n{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
