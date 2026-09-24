"""0.1.3 — the truncation gap, closed with an external witness.

A hash chain provably cannot detect truncation: drop the last N rows and the
surviving prefix still chains clean, so through 0.1.2 a log truncated BEFORE
export earned a clean PASS. These tests are written FAILING against 0.1.2 (no
`witness` parameter, no distinguished verdict) and pass on 0.1.3.

Run: python -m pytest test_witness_truncation.py -q
"""
import json
import tempfile
from pathlib import Path

import pytest

from arcaeon.prove.audit import AuditLog, export_bundle
from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger.witness import WitnessStore, publish_head


def _log(d, n=4):
    p = Path(d) / "audit.jsonl"
    log = AuditLog(p, system_id="triage-v3", provider="Acme AI")
    for i in range(n):
        log.record(event="decision", agent="triage-v3", decision=f"d{i}")
    return log, p


def _witness(d):
    return WitnessStore(Path(d) / "witness.jsonl")


# ---------------------------------------------------------------------------
# The gap itself: a truncated-but-chain-clean log. 0.1.2 called it PASS.
# ---------------------------------------------------------------------------

def test_truncated_log_still_chains_clean_but_is_not_pass_without_witness():
    """chain_ok stays True on a truncated prefix — that is the whole gap. The
    new default refuses to call it PASS: it says verified-modulo-truncation."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=4)
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")   # 4 -> 2
        out = log.export_bundle(Path(d) / "bundle")
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["chain_ok"] is True                 # the chain can't see it
        assert integ["finding"] == "VERIFIED_MODULO_TRUNCATION"
        assert integ["truncation_checked"] is False
        assert integ["truncation_ok"] is None
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        assert "TRUNCATION NOT CHECKED" in summary
        assert "PASS —" not in summary                    # never a clean pass


def test_truncated_log_with_witness_is_TRUNCATION_DETECTED():
    """The load-bearing test: pin at 4 rows, truncate to 2, export against the
    witness. Must be TRUNCATION_DETECTED — the 0.1.2 PASS is gone."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=4)
        store, ns = _witness(d), "acme/triage-v3"
        publish_head(store, ns, Ledger(p))               # witness sees 4 rows
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")   # 4 -> 2
        out = export_bundle(p, Path(d) / "bundle", system_id="triage-v3",
                            witness=store, witness_namespace=ns)
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["finding"] == "TRUNCATION_DETECTED"
        assert integ["chain_ok"] is True
        assert integ["truncation_checked"] is True
        assert integ["truncation_ok"] is False
        assert integ["witness"]["verdict"] == "truncated"
        assert integ["witness"]["witness_rows"] == 4
        assert integ["witness"]["local_rows"] == 2
        # a durable witness.json cross-reference is written into the bundle
        wj = json.loads((out / "witness.json").read_text(encoding="utf-8"))
        assert wj["verdict"] == "truncated"
        assert wj["pin"]["rows"] == 4
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        assert "TRUNCATION_DETECTED" in summary


def test_untruncated_log_with_witness_is_PASS():
    """Pin at 4 rows, export unchanged against the witness — full PASS: the only
    verdict allowed to claim completeness, because truncation was checked."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=4)
        store, ns = _witness(d), "acme/triage-v3"
        publish_head(store, ns, Ledger(p))
        out = export_bundle(p, Path(d) / "bundle", witness=store,
                            witness_namespace=ns)
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["finding"] == "PASS"
        assert integ["chain_ok"] is True
        assert integ["truncation_checked"] is True
        assert integ["truncation_ok"] is True


def test_witness_configured_but_no_pin_is_a_failed_check_not_honest_skip():
    """SUPERSEDES the pre-C9 behavior this test used to assert (VERIFIED_
    MODULO_TRUNCATION). A witness AND namespace both explicitly configured,
    with nothing pinned there, is not the same as never asking: it is
    indistinguishable, by the caller who typo'd the namespace, from a silently
    disabled check. Pre-invite audit C9 (2026-08-23) reclassified this as
    WITNESS_CHECK_FAILED — a check that could not complete, exit 2, not a clean
    skip at exit 0. The genuinely honest no-witness-at-all case is covered
    separately below and is UNCHANGED by this fix."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=3)
        store, ns = _witness(d), "acme/triage-v3"           # never pinned
        out = export_bundle(p, Path(d) / "bundle", witness=store,
                            witness_namespace=ns)
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["finding"] == "WITNESS_CHECK_FAILED"
        assert integ["truncation_checked"] is False
        assert integ["witness"]["verdict"] == "no_record"
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        assert "WITNESS_CHECK_FAILED" in summary


def test_no_witness_at_all_is_still_the_honest_non_proof():
    """The case C9 must NOT touch: nobody configured a witness at all. That
    stays VERIFIED_MODULO_TRUNCATION — an honest non-proof, never an
    accusation with nothing behind it."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=3)
        out = export_bundle(p, Path(d) / "bundle")  # no witness
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["finding"] == "VERIFIED_MODULO_TRUNCATION"


def test_rewritten_log_with_witness_is_REWRITE_DETECTED():
    """Re-mint the whole log with different content: it chains clean internally
    but disagrees with the witnessed head. Caught as a rewrite, not a PASS."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=3)
        store, ns = _witness(d), "acme/triage-v3"
        publish_head(store, ns, Ledger(p))
        p.unlink()
        log2 = AuditLog(p, system_id="triage-v3", provider="Acme AI")
        for i in range(3):
            log2.record(event="decision", agent="triage-v3", decision=f"forged{i}")
        out = export_bundle(p, Path(d) / "bundle", witness=store,
                            witness_namespace=ns)
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["chain_ok"] is True                    # internally consistent
        assert integ["finding"] == "REWRITE_DETECTED"
        assert integ["witness"]["verdict"] == "rewritten"


def test_no_witness_argument_stays_honest_default():
    """No witness at all (the common case): verified-modulo-truncation, and the
    bundle writes no witness.json (nothing was consulted)."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=3)
        out = export_bundle(p, Path(d) / "bundle")
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["finding"] == "VERIFIED_MODULO_TRUNCATION"
        assert integ["truncation_checked"] is False
        # v2 schema: witness is a NATURE block, not None — kind 'none' when unconsulted
        assert integ["witness"]["kind"] == "none"
        assert integ["witness"]["independence"] == "none"
        assert not (out / "witness.json").exists()


def test_auditlog_carries_witness_config_and_pins():
    """Ergonomic path: witness set on the AuditLog, pin_to_witness(), export()
    picks it up with no per-call args."""
    with tempfile.TemporaryDirectory() as d:
        store, ns = _witness(d), "acme/triage-v3"
        p = Path(d) / "audit.jsonl"
        log = AuditLog(p, system_id="triage-v3", witness=store,
                       witness_namespace=ns)
        for i in range(3):
            log.record(event="decision", agent="triage-v3", decision=f"d{i}")
        log.pin_to_witness()
        out = log.export_bundle(Path(d) / "bundle")
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["finding"] == "PASS"
        assert integ["truncation_ok"] is True


# ---------------------------------------------------------------------------
# 0.1.4 — witness NATURE surfaced in integrity.json so a regulator can judge
# INDEPENDENCE (local self-controlled file vs. independent remote notary).
# ---------------------------------------------------------------------------

from arcaeon.prove.audit import witness_nature_of, BUNDLE_SCHEMA_VERSION


def test_local_file_witness_labelled_self_asserted_not_independent():
    """A local-file witness (the reference/default) must be labelled honestly: a
    PASS backed by it is self_asserted, NOT independent."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=4)
        store, ns = _witness(d), "acme/triage-v3"
        publish_head(store, ns, Ledger(p))
        out = export_bundle(p, Path(d) / "bundle", witness=store, witness_namespace=ns)
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["finding"] == "PASS"
        w = integ["witness"]
        assert w["kind"] == "local_file"
        assert w["independence"] == "self_asserted"
        assert "NOT independent" in w["note"]
        assert integ["bundle_schema"] == BUNDLE_SCHEMA_VERSION
        # the verification fields still ride alongside the nature fields
        assert w["verdict"] == "consistent"
        # witness.json mirrors the merged block
        wj = json.loads((out / "witness.json").read_text(encoding="utf-8"))
        assert wj["kind"] == "local_file" and wj["independence"] == "self_asserted"


def test_no_witness_reports_kind_none():
    """No witness → witness block is present with kind 'none' / independence 'none'."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=3)
        out = export_bundle(p, Path(d) / "bundle")
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["witness"]["kind"] == "none"
        assert integ["witness"]["independence"] == "none"
        assert not (out / "witness.json").exists()


def test_self_declared_remote_witness_is_externally_verifiable():
    """A witness object may declare its own nature via witness_descriptor() — how a
    hosted/OTS client advertises externally_verifiable independence."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=3)
        base, ns = _witness(d), "acme/triage-v3"
        publish_head(base, ns, Ledger(p))

        class RemoteWitness:
            """Thin client wrapper that self-describes as an independent notary."""
            def __init__(self, inner):
                self._inner = inner
            def latest(self, namespace):
                return self._inner.latest(namespace)
            def witness_descriptor(self):
                return {"kind": "remote_url",
                        "identifier": "https://notary.example/acme",
                        "independence": "externally_verifiable"}

        out = export_bundle(p, Path(d) / "bundle",
                            witness=RemoteWitness(base), witness_namespace=ns)
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        w = integ["witness"]
        assert w["kind"] == "remote_url"
        assert w["identifier"] == "https://notary.example/acme"
        assert w["independence"] == "externally_verifiable"
        assert integ["finding"] == "PASS"


def test_old_bundle_without_nature_block_reads_as_unknown():
    """Back-compat: a pre-v2 integrity.json (witness = verification-only, or absent)
    reads back as kind 'unknown' via witness_nature_of — never a crash, never a
    guessed independence."""
    # legacy shape 1: witness held only the verification verdict (no kind field)
    legacy = {"verdict": "PASS", "witness": {"namespace": "acme/x",
              "verdict": "consistent", "witness_rows": 4}}
    n = witness_nature_of(legacy)
    assert n["kind"] == "unknown"
    assert n["independence"] == "unknown"
    # legacy shape 2: no witness key at all
    assert witness_nature_of({"verdict": "FAIL"})["kind"] == "unknown"
    # legacy shape 3: witness was None (0.1.3 no-witness bundle)
    assert witness_nature_of({"witness": None})["kind"] == "unknown"
    # a v2 block passes straight through
    v2 = {"witness": {"kind": "local_file", "independence": "self_asserted"}}
    assert witness_nature_of(v2)["kind"] == "local_file"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


# ---------------------------------------------------------------------------
# 0.1.5 — THE OVERSHOOT. The 2026-08-23 tri-state fix corrected a false-FAIL
# (a day-one empty log was accused of tampering) and overshot into a false-PASS:
# `verify_file` returns ok=None for TWO different reasons — an empty file
# (scope "empty") and unchained rows skipped (scope "bounded_prechain_skipped")
# — and export_bundle collapsed both into EMPTY_LOG. Because that branch ran
# FIRST, it also masked a positive witness detection.
#
# Planted red for the class: strip every chain link, alter a witnessed row,
# delete witnessed rows. The witness says "truncated". The export must NOT say
# "no records have been written yet".
# ---------------------------------------------------------------------------

def _strip_chain(p: Path):
    """Remove the chain key from every row — the whole file becomes prechain."""
    import re
    rows = p.read_text(encoding="utf-8").strip().split("\n")
    rows = [re.sub(r',\s*"chain":\s*"[0-9a-f]+"\s*\}$', "}", r) for r in rows]
    p.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return rows


def test_unchained_tampered_log_is_not_reported_as_empty():
    """A log with rows in it must never export as EMPTY_LOG, and a positive
    witness detection must never be masked by a chain-scope verdict."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=10)
        store = _witness(d)
        publish_head(store, "acme-prod", Ledger(p))

        rows = _strip_chain(p)
        rows[3] = rows[3].replace('"d3"', '"TAMPERED"')
        p.write_text("\n".join(rows[:7]) + "\n", encoding="utf-8")

        out = Path(d) / "bundle"
        export_bundle(str(p), str(out), witness=str(store.path),
                      witness_namespace="acme-prod")
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))

        assert integ["truncation_ok"] is False, "witness detection must survive"
        assert integ["verdict"] != "EMPTY_LOG", (
            "7 rows present, 3 witnessed rows deleted, witness said truncated — "
            f"but the export verdict was {integ['verdict']!r}"
        )
        assert integ["finding"] == "TRUNCATION_DETECTED", integ["verdict"]

        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        assert "no records have been written yet" not in summary


def test_genuinely_empty_log_still_reports_empty():
    """The control: the original false-FAIL fix must NOT regress. A real empty
    file is still EMPTY_LOG, never an accusation."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "audit.jsonl"
        p.write_text("", encoding="utf-8")
        out = Path(d) / "bundle"
        export_bundle(str(p), str(out))
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["finding"] == "EMPTY_LOG", integ["verdict"]


def test_unchained_but_untampered_log_is_not_called_empty():
    """An honest ADOPTER (legacy rows, no chain yet, no witness) must not be
    told 'no records have been written yet' either — that is the same bug
    hitting a paying customer who did nothing wrong."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=5)
        _strip_chain(p)
        out = Path(d) / "bundle"
        export_bundle(str(p), str(out))
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["rows"] == 5
        assert integ["verdict"] != "EMPTY_LOG", (
            "5 real rows exported as EMPTY_LOG — the adopter path"
        )


# ---------------------------------------------------------------------------
# SELF-AUDIT (2026-08-23, hours after shipping the fix): arcaeon-ledger gained
# `witness_self_integrity` so a consumer could tell "the witness proved its own
# record was unedited" from "it could not". Nothing read it. The ledger set it,
# its own tests asserted it, and THIS package -- whose entire PASS rests on the
# witness -- never looked. A field that records the answer and tells no consumer
# is the same failure it was built to close, moved one file over.
#
# Every remote/hosted witness client exposes only .latest(), which is exactly the
# shape that cannot self-verify, so this is the deployment case and not an edge.
# ---------------------------------------------------------------------------

class _LatestOnlyWitness:
    """A hosted-witness client as the documented contract allows: .latest() only."""

    def __init__(self, pin):
        self._pin = pin

    def latest(self, namespace):
        return dict(self._pin)


def test_pass_over_a_witness_that_cannot_self_verify_says_so(tmp_path):
    """The forged-pin case: delete rows, forge the pin to match, deliver it
    through a hosted-shaped client. The comparison agrees -- that is what
    forging means -- so the bundle MUST carry the caveat, or the PASS is a lie
    of omission."""
    log = tmp_path / "audit.jsonl"
    led = Ledger(log)
    for i in range(6):
        led.append({"e": i})
    rows = log.read_text(encoding="utf-8").strip().split("\n")
    log.write_text("\n".join(rows[:3]) + "\n", encoding="utf-8")   # 3 deleted
    forged = Ledger(log).head()                                    # re-pin to match

    client = _LatestOnlyWitness({"namespace": "ns", "rows": forged.rows,
                                 "chain": forged.chain})
    out = tmp_path / "bundle"
    export_bundle(str(log), str(out), witness=client, witness_namespace="ns")

    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    assert integ["witness"]["self_integrity"] == "unestablished", (
        "the consumer must SURFACE that the witness never proved its own "
        f"integrity; got {integ['witness'].get('self_integrity')!r}"
    )

    summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
    if integ["finding"] == "PASS":
        assert "did NOT prove its own record was unedited" in summary, (
            "a PASS resting on a witness that could not self-verify must say so "
            "in the document a reader actually reads"
        )


def test_real_store_pass_carries_no_spurious_warning(tmp_path):
    """The green control: a real WitnessStore CAN self-verify, so the caveat must
    be ABSENT. Without this, the warning could print on every export and become
    the boilerplate everyone learns to skip."""
    log = tmp_path / "audit.jsonl"
    led = Ledger(log)
    for i in range(4):
        led.append({"e": i})
    store = WitnessStore(tmp_path / "w.jsonl")
    publish_head(store, "ns", Ledger(log))

    out = tmp_path / "bundle"
    export_bundle(str(log), str(out), witness=str(store.path), witness_namespace="ns")
    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    assert integ["finding"] == "PASS", integ["verdict"]
    assert integ["witness"]["self_integrity"] == "verified"
    summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
    assert "did NOT prove its own record was unedited" not in summary


# ---------------------------------------------------------------------------
# C6 (pre-invite audit): "independent verification" quietly reduced to trusting
# the audited party. The bundle's how_to_reverify was one line -- re-run OUR
# tool over bytes WE handed the reader -- which checks the chain and says
# nothing a third party could not have been handed. Completeness rode on
# witness.json, a copy the log's OWNER generated.
#
# The fix was already built and deployed and referenced nowhere: a public,
# no-auth GET against a witness whose pin store is a PUBLIC git repo.
# ---------------------------------------------------------------------------

def test_bundle_tells_a_stranger_where_to_check_us_from_outside(tmp_path):
    log = tmp_path / "audit.jsonl"
    led = Ledger(log)
    for i in range(5):
        led.append({"e": i})
    store = WitnessStore(tmp_path / "w.jsonl")
    publish_head(store, "acme-prod", Ledger(log))

    out = tmp_path / "bundle"
    export_bundle(str(log), str(out), witness=str(store.path),
                  witness_namespace="acme-prod")
    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    recipe = integ["how_to_reverify"]

    assert isinstance(recipe, dict), "the recipe must name its steps, not be one string"
    indep = recipe["step_2_completeness_INDEPENDENT"]
    assert "witness.arcaeon.io" in indep["run"], indep
    assert "acme-prod" in indep["run"], "the query must be prefilled with THIS bundle's namespace"
    assert indep["no_credential_required"] is True

    # the chain step must stop advertising itself as sufficient
    assert "not independent" in recipe["step_1_chain"]["what_it_proves"].lower()
    assert "tri-state" in recipe["step_1_chain"]["note"].lower()

    # and the human-readable document must carry it too -- integrity.json is not
    # where a regulator looks first
    summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
    assert "WITHOUT TRUSTING US" in summary
    assert "witness.arcaeon.io/api/verify?ns=acme-prod" in summary
    assert "believe the public repository" in summary


def test_bundle_with_no_witness_says_completeness_was_not_established(tmp_path):
    """The green control: with nothing to fetch, the bundle must NOT imply a
    third party can check completeness. Silence here would be the same
    self-attestation problem wearing a friendlier face."""
    log = tmp_path / "audit.jsonl"
    led = Ledger(log)
    for i in range(3):
        led.append({"e": i})

    out = tmp_path / "bundle"
    export_bundle(str(log), str(out))
    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    indep = integ["how_to_reverify"]["step_2_completeness_INDEPENDENT"]
    assert "unavailable" in indep
    assert "NOT independently established" in indep["unavailable"]
    summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
    assert "WITHOUT TRUSTING US" not in summary, (
        "must not advertise an external check when there is nothing to fetch"
    )


# ---------------------------------------------------------------------------
# C4 (pre-invite audit): `independence` is the field a regulator uses to weigh a
# PASS, and the audited party could set it by OMISSION.
#
# Two defects, one branch: it defaulted to the STRONGEST label when a descriptor
# left it out, and the honest isinstance(WitnessStore) check sat AFTER the
# descriptor branch -- reachable only by a store that declined to describe
# itself. A four-line shim wrapping a local file in the log owner's own
# directory earned `externally_verifiable` without the URL ever being contacted.
# ---------------------------------------------------------------------------

class _ShimWitness:
    """The attack, verbatim from the audit: wrap a local file, describe yourself
    as a remote notary, omit `independence` entirely."""

    def __init__(self, inner):
        self._inner = inner

    def latest(self, ns):
        return self._inner.latest(ns)

    def witness_descriptor(self):
        return {"kind": "remote_url", "identifier": "https://notary.example/acme"}


class _LocalFileLiar(WitnessStore):
    """A real local file that ALSO self-describes as an external notary."""

    def witness_descriptor(self):
        return {"kind": "opentimestamps", "identifier": "btc:000000000019d668",
                "independence": "externally_verifiable"}


def test_omitting_independence_does_not_earn_the_strongest_label(tmp_path):
    log = tmp_path / "a.jsonl"
    led = Ledger(log)
    for i in range(3):
        led.append({"e": i})
    inner = WitnessStore(tmp_path / "w.jsonl")
    publish_head(inner, "ns", Ledger(log))

    out = tmp_path / "bundle"
    export_bundle(str(log), str(out), witness=_ShimWitness(inner), witness_namespace="ns")
    w = json.loads((out / "integrity.json").read_text(encoding="utf-8"))["witness"]

    assert w["independence"] != "externally_verifiable", (
        "omitting the field earned the strongest label"
    )
    assert w["independence"] == "undeclared", w
    assert w["independence_source"] == "self_declared_by_witness"


def test_a_local_file_cannot_self_describe_its_way_to_independence(tmp_path):
    """What we can ESTABLISH must outrank what the object CLAIMS."""
    log = tmp_path / "a.jsonl"
    led = Ledger(log)
    for i in range(3):
        led.append({"e": i})
    liar = _LocalFileLiar(tmp_path / "w.jsonl")
    publish_head(liar, "ns", Ledger(log))

    out = tmp_path / "bundle"
    export_bundle(str(log), str(out), witness=liar, witness_namespace="ns")
    w = json.loads((out / "integrity.json").read_text(encoding="utf-8"))["witness"]

    assert w["kind"] == "local_file", w
    assert w["independence"] == "self_asserted", w
    assert w["independence_source"] == "established_by_type"
    assert "Bitcoin" not in (w.get("note") or ""), (
        "a local file must not emit prose asserting a blockchain anchor"
    )


def test_self_declared_independence_is_labelled_as_self_declared(tmp_path):
    """A descriptor CAN still declare external verifiability with a re-fetchable
    identifier -- but the bundle must say who made the claim, not launder it."""
    log = tmp_path / "a.jsonl"
    led = Ledger(log)
    for i in range(3):
        led.append({"e": i})
    inner = WitnessStore(tmp_path / "w.jsonl")
    publish_head(inner, "ns", Ledger(log))

    class _Declared(_ShimWitness):
        def witness_descriptor(self):
            return {"kind": "remote_url", "identifier": "https://notary.example/acme",
                    "independence": "externally_verifiable"}

    out = tmp_path / "bundle"
    export_bundle(str(log), str(out), witness=_Declared(inner), witness_namespace="ns")
    w = json.loads((out / "integrity.json").read_text(encoding="utf-8"))["witness"]
    assert w["independence"] == "externally_verifiable"
    assert w["independence_source"] == "self_declared_by_witness"
    assert "SELF-DECLARED" in w["note"], w["note"]


# ---------------------------------------------------------------------------
# C9 (pre-invite adversarial audit, 2026-08-23): a mistyped or miscased
# namespace silently disables the truncation check and still exits 0.
#
# When a caller explicitly configures BOTH a witness and a namespace, no_record
# means "I asked a specific namespace and found nothing there" -- which used to
# render IDENTICALLY to "no witness was ever configured" (VERIFIED_MODULO_
# TRUNCATION, exit 0). The person who chooses the namespace string is the
# person being audited, and a typo there silently turned off their own check
# with no visible cost.
# ---------------------------------------------------------------------------

def test_configured_but_unanswered_namespace_is_a_failed_check_not_a_skip(tmp_path):
    log = tmp_path / "a.jsonl"
    led = Ledger(log)
    for i in range(3):
        led.append({"e": i})
    store = WitnessStore(tmp_path / "w.jsonl")
    publish_head(store, "acme-prod", Ledger(log))

    out = tmp_path / "bundle"
    # explicitly configured witness AND namespace -- but the WRONG namespace,
    # exactly what a typo or a case mismatch produces
    export_bundle(str(log), str(out), witness=str(store.path),
                  witness_namespace="acme-prod-TYPO")
    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))

    assert integ["verdict"] != "VERIFIED_MODULO_TRUNCATION", (
        "a configured-but-wrong namespace read identically to never asking"
    )
    assert integ["finding"] == "WITNESS_CHECK_FAILED", integ["verdict"]


def test_no_witness_configured_at_all_is_still_the_honest_non_proof(tmp_path):
    """GREEN CONTROL: someone who never configured a witness must NOT be told
    their check failed -- that would be an accusation with nothing behind it."""
    log = tmp_path / "a.jsonl"
    led = Ledger(log)
    for i in range(3):
        led.append({"e": i})
    out = tmp_path / "bundle"
    export_bundle(str(log), str(out))  # no witness at all
    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    assert integ["finding"] == "VERIFIED_MODULO_TRUNCATION", integ["verdict"]


def test_correctly_pinned_namespace_still_passes(tmp_path):
    """Second control: this must not break the ordinary success path."""
    log = tmp_path / "a.jsonl"
    led = Ledger(log)
    for i in range(3):
        led.append({"e": i})
    store = WitnessStore(tmp_path / "w.jsonl")
    publish_head(store, "acme-prod", Ledger(log))
    out = tmp_path / "bundle"
    export_bundle(str(log), str(out), witness=str(store.path), witness_namespace="acme-prod")
    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    assert integ["finding"] == "PASS", integ["verdict"]


# ---------------------------------------------------------------------------
# AUDIT 2026-08-28. Two places where the verdict was right and the SENTENCE
# next to it was false. A regulator reads the sentence; a bundle whose prose
# contradicts its own integrity.json has laundered a skipped check into a
# clean-looking one, which is the same failure C9 closed one argument over.
# ---------------------------------------------------------------------------

def test_witness_without_namespace_does_not_claim_no_witness_was_consulted():
    """`--witness w.jsonl` with `--namespace` FORGOTTEN silently performs no
    truncation check and prints 'no external witness was consulted' — over a
    run where one was configured, and whose own integrity.json records
    witness.kind == 'local_file'. The operator asked for the check; the bundle
    must say the check was not RUN, not that it was never ASKED FOR."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=4)
        store = _witness(d)
        publish_head(store, "acme/triage-v3", Ledger(p))

        out = Path(d) / "bundle"
        export_bundle(str(p), str(out), witness=str(store.path))  # no namespace
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")

        # integrity.json already knows a witness was configured
        assert integ["witness"]["kind"] == "local_file"
        assert integ["truncation_checked"] is False
        # ...so the prose must not contradict it
        assert "no external witness was consulted" not in summary, (
            "a witness WAS configured; the summary says none was consulted — "
            "the bundle contradicts its own witness block")
        assert "namespace" in summary, (
            "the summary must name WHY the configured witness went unused")


def test_declared_break_scope_is_not_described_as_zero_unchained_rows():
    """`bounded_declared_break` (ledger 0.6.0) has prechain == 0: the rows are
    chained, one break is DECLARED. The message hardcodes the prechain story,
    so it renders 'the chain could not speak for 0 of them: they carry no chain
    links' — a sentence that contradicts itself and names the wrong cause."""
    from arcaeon.record.ledger import declare_break, verify_file

    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=4)
        lines = p.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[2])
        row["decision"] = "OUT_OF_BAND"
        lines[2] = json.dumps(row)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        declare_break(p, 3, "rewritten out of band by a legacy tool")

        vr = verify_file(p)
        assert vr.verified_scope == "bounded_declared_break"
        assert vr.prechain == 0

        out = Path(d) / "bundle"
        export_bundle(str(p), str(out))
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")

        assert integ["finding"] == "UNVERIFIED_SCOPE"       # verdict is right
        assert "for 0 of them" not in summary, (
            "the summary says 0 rows were unverifiable while reporting an "
            "unverified scope — it printed the prechain count for a "
            "declared-break scope")
        assert "declared" in summary.lower(), (
            "the summary must name the declared break as the reason the scan "
            "was bounded")
