"""AB 1405 (Cal. Gov. Code S11549.83(d)(1)) report-element fields: optional,
backward-compatible carriers for elements (A) engagement scope, (C)
remediation, (D) internal-standards adherence, and (F) attestation.

See projects/arcaeon/AB1405_REPORT_ELEMENT_MAP_2026-09-15.md for the
statute-to-field mapping these fields implement, and core.py's "AB 1405
report-element carriers" section for what each one is and, critically, who
is allowed to fill it in (always the auditor, never this tool).

Elements (B) results/documentation and (E) audit limitations are NOT tested
here -- they are the pre-existing `checks`/`subject` and the mandatory
`scope["does_not_prove"]`, already covered by test_receipts.py.
"""
import pytest

from arcaeon.record.receipt import (ADHERENCE_VALUES, attach_attestation_signature,
                             attestation, build_receipt, engagement_scope,
                             render_exhibit, verify_receipt)

SCOPE = {"proves": ["p"], "does_not_prove": ["d"]}


def _ab1405_receipt(tmp_path, ledger_name="l.jsonl"):
    subject = {"a": 1,
              "internal_standards_ref": "ACME-SAFE-STD-v3 (https://acme.example/std/v3)"}
    checks = [{"status": "found"},
             {"status": "flagged", "flagged": True,
              "remediation": "add a second reviewer before the action fires",
              "adherence": "not_adhered"}]
    extra = {**engagement_scope("Audit of Acme's dispatch model, Jan-Mar 2026, "
                                "against AB 1405."),
             **attestation("This audit was conducted in accordance with the "
                          "requirements of this chapter.",
                          "J. Rivera, Registered AI Auditor #1234",
                          auditor_registry_id="CA-AIA-1234",
                          signed_at="2026-09-15T00:00:00Z")}
    return build_receipt("x", subject, checks, SCOPE, ledger_path=tmp_path / ledger_name,
                         namespace="t", witness=False, anchor=False, extra=extra)


# --------------------------------------------------------------------------
# (a) a receipt with all four fields builds, verifies, and the fields are
#     in the digest
# --------------------------------------------------------------------------

def test_all_four_fields_build_and_verify(tmp_path):
    rc = _ab1405_receipt(tmp_path)
    assert rc["extra"]["engagement_scope"].startswith("Audit of Acme's")
    assert rc["subject"]["internal_standards_ref"].startswith("ACME-SAFE-STD")
    assert rc["checks"][1]["remediation"] == "add a second reviewer before the action fires"
    assert rc["checks"][1]["adherence"] == "not_adhered"
    att = rc["extra"]["attestation"]
    assert att["statement"].startswith("This audit was conducted")
    assert att["auditor_name"] == "J. Rivera, Registered AI Auditor #1234"
    assert att["auditor_registry_id"] == "CA-AIA-1234"
    assert att["signed_at"] == "2026-09-15T00:00:00Z"

    res = verify_receipt(rc, ledger_path=tmp_path / "l.jsonl")
    assert res["ok"] and res["body_digest_ok"]

    # the fields are genuinely INSIDE the digest, not printed alongside it:
    # every one of subject/checks/extra is a member of core.BODY_FIELDS.
    import arcaeon.record.receipt.core as core
    assert {"subject", "checks", "extra"} <= set(core.BODY_FIELDS)


# --------------------------------------------------------------------------
# (b) tampering any of the four fields fails verification
# --------------------------------------------------------------------------

@pytest.mark.parametrize("mutate,label", [
    (lambda rc: rc["extra"].__setitem__("engagement_scope", "tampered"), "engagement_scope"),
    (lambda rc: rc["checks"][1].__setitem__("remediation", "tampered"), "remediation"),
    (lambda rc: rc["subject"].__setitem__("internal_standards_ref", "tampered"), "internal_standards_ref"),
    (lambda rc: rc["checks"][1].__setitem__("adherence", "adhered"), "adherence"),
    (lambda rc: rc["extra"]["attestation"].__setitem__("statement", "tampered"), "attestation.statement"),
    (lambda rc: rc["extra"]["attestation"].__setitem__("auditor_name", "tampered"), "attestation.auditor_name"),
    (lambda rc: rc["extra"]["attestation"].__setitem__("signed_at", "2099-01-01T00:00:00Z"), "attestation.signed_at"),
])
def test_tampering_any_field_breaks_verification(tmp_path, mutate, label):
    rc = _ab1405_receipt(tmp_path)
    mutate(rc)
    res = verify_receipt(rc, ledger_path=tmp_path / "l.jsonl")
    assert not res["ok"], f"tampering {label} should have broken verification"
    assert not res["body_digest_ok"], f"tampering {label} should have broken the body digest"


# --------------------------------------------------------------------------
# (c) an old receipt without them still verifies
# --------------------------------------------------------------------------

def test_old_receipt_without_the_fields_still_verifies(tmp_path):
    rc = build_receipt("x", {"a": 1}, [{"status": "found"}], SCOPE,
                       ledger_path=tmp_path / "l.jsonl", namespace="t",
                       witness=False, anchor=False)
    assert "attestation" not in (rc.get("extra") or {})
    assert "engagement_scope" not in (rc.get("extra") or {})
    assert "internal_standards_ref" not in rc["subject"]
    assert "remediation" not in rc["checks"][0] and "adherence" not in rc["checks"][0]
    res = verify_receipt(rc, ledger_path=tmp_path / "l.jsonl")
    assert res["ok"] and res["body_digest_ok"]


def test_committed_example_receipts_still_verify_byte_for_byte():
    """The literal existing-fixture guarantee: a receipt minted before this
    feature existed must still verify, unmodified, against its own
    committed ledger."""
    import json
    from pathlib import Path

    from arcaeon.record.receipt import load_receipt

    examples = Path(__file__).parent.parent / "examples" / "ballots"
    if not examples.exists():
        pytest.skip("examples/ballots/ not present in this checkout")
    receipts = sorted(examples.glob("*.receipt.json"))
    assert receipts, "expected at least one committed example receipt"
    checked = 0
    for rp in receipts:
        rc = load_receipt(rp)
        ledger_path = examples / json.loads(rp.read_text(encoding="utf-8"))["ledger"]["path"]
        if not ledger_path.exists():
            continue
        res = verify_receipt(rc, ledger_path=ledger_path)
        assert res["body_digest_ok"], f"{rp.name} body digest should still recompute"
        checked += 1
    assert checked > 0


# --------------------------------------------------------------------------
# (d) attestation present does NOT change the verifier's verdict semantics
# --------------------------------------------------------------------------

def test_attestation_never_changes_verdict_semantics_or_claims_compliance(tmp_path):
    plain = build_receipt("x", {"a": 1}, [{"status": "found"}], SCOPE,
                          ledger_path=tmp_path / "l1.jsonl", namespace="t",
                          witness=False, anchor=False)
    branded = _ab1405_receipt(tmp_path, ledger_name="l2.jsonl")

    r1 = verify_receipt(plain, ledger_path=tmp_path / "l1.jsonl")
    r2 = verify_receipt(branded, ledger_path=tmp_path / "l2.jsonl")
    assert r1["ok"] and r2["ok"]
    # attestation's presence adds no new verdict key and changes no
    # existing one's meaning -- both results have the identical shape.
    assert set(r1.keys()) == set(r2.keys())
    assert set(r1["ledger"].keys()) == set(r2["ledger"].keys())

    for out in (render_exhibit(plain), render_exhibit(branded)):
        low = out.lower()
        assert "compliant" not in low
        assert "complies" not in low
        assert "in compliance" not in low


def test_exhibit_renders_ab1405_elements_only_when_present(tmp_path):
    plain = build_receipt("x", {"a": 1}, [{"status": "found"}], SCOPE,
                          ledger_path=tmp_path / "l1.jsonl", namespace="t",
                          witness=False, anchor=False)
    assert "AB 1405" not in render_exhibit(plain)

    branded = _ab1405_receipt(tmp_path, ledger_name="l2.jsonl")
    ex = render_exhibit(branded)
    assert "AB 1405 REPORT ELEMENTS" in ex
    assert "auditor-supplied; not asserted by this tool" in ex
    assert "engagement scope" in ex
    assert "remediation" in ex
    assert "adherence" in ex
    assert "attestation" in ex


# --------------------------------------------------------------------------
# supporting behavior: enum validation, absent-writes-no-key, and the
# detached-signature boundary
# --------------------------------------------------------------------------

def test_invalid_adherence_value_refused_valid_values_accepted(tmp_path):
    with pytest.raises(ValueError):
        build_receipt("x", {}, [{"adherence": "sort of"}], SCOPE,
                      ledger_path=tmp_path / "l.jsonl", namespace="t",
                      witness=False, anchor=False)
    for i, v in enumerate(ADHERENCE_VALUES):
        rc = build_receipt("x", {}, [{"adherence": v}], SCOPE,
                           ledger_path=tmp_path / f"l{i}.jsonl", namespace="t",
                           witness=False, anchor=False)
        assert rc["checks"][0]["adherence"] == v


def test_engagement_scope_and_attestation_absent_write_no_key():
    assert engagement_scope("") == {}
    assert engagement_scope("   ") == {}
    assert engagement_scope(None) == {}
    assert attestation("", "someone") == {}
    assert attestation("statement", "") == {}
    assert attestation(None, None) == {}


def test_attestation_signature_is_detached_outside_the_digest(tmp_path):
    rc = _ab1405_receipt(tmp_path)
    before = verify_receipt(rc, ledger_path=tmp_path / "l.jsonl")
    assert before["ok"]

    attach_attestation_signature(rc, "deadbeef" * 8, algorithm="ed25519")
    assert rc["attestation_signature"]["value"] == "deadbeef" * 8
    assert rc["attestation_signature"]["body_digest"] == rc["body_digest"]

    after = verify_receipt(rc, ledger_path=tmp_path / "l.jsonl")
    assert after["ok"] and after["body_digest_ok"]

    # tampering the detached signature must NOT break body verification --
    # it lives outside core.BODY_FIELDS by construction (see
    # core.attach_attestation_signature's docstring for why: a signature
    # over the body digest cannot also be one of the digest's own inputs).
    rc["attestation_signature"]["value"] = "tampered"
    still = verify_receipt(rc, ledger_path=tmp_path / "l.jsonl")
    assert still["ok"] and still["body_digest_ok"]
    # ...and it is never reported as checked either (2026-09-22): the format
    # carries no key, so the value's verdict is could_not_look.
    assert still["attestation_signature"]["verdict"] == "could_not_look"
    assert after["attestation_signature"]["verdict"] == "could_not_look"

    import arcaeon.record.receipt.core as core
    assert "attestation_signature" not in core.BODY_FIELDS
