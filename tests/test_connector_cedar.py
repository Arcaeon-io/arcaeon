# SPDX-License-Identifier: MIT
"""L2-06: a Cedar authorization response (the cedar-policy library's decision +
diagnostics), an Amazon Verified Permissions IsAuthorized response, or a
CloudTrail data event for IsAuthorized / BatchIsAuthorized becomes relayed check
rows on connector.core. Cedar does not sign its decisions, so every row is
signed_by_vendor false and reported by the sender. The fixtures are synthetic,
shape from the research note, not a live capture. No network, no AWS."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest

from arcaeon.connector import ROW_KIND, VendorAdapter, adapter_for, import_verdict, recheck
from arcaeon.connector import cedar as C
from arcaeon.connector.core import MAX_STR
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "cedar"


def _fx(name: str) -> bytes:
    return (FIX / name).read_bytes()


CEDAR_ALLOW = _fx("cedar_allow.json")
CEDAR_DENY = _fx("cedar_deny.json")
CEDAR_ERR = _fx("cedar_allow_with_errors.json")
AVP_ALLOW = _fx("avp_allow.json")
AVP_IMPLICIT = _fx("avp_deny_implicit.json")
AVP_ERR = _fx("avp_errors.json")
AVP_CAP = _fx("avp_capitalised.json")
CT_ONE = _fx("cloudtrail_isauthorized.json")
CT_BATCH = _fx("cloudtrail_batch.json")
SIGNED_LOOKING = _fx("signature_looking.json")
ALL_FIXTURES = (CEDAR_ALLOW, CEDAR_DENY, CEDAR_ERR, AVP_ALLOW, AVP_IMPLICIT, AVP_ERR, AVP_CAP,
                CT_ONE, CT_BATCH, SIGNED_LOOKING)
AT = "2026-10-05T12:00:00Z"


def _rows(raw=CEDAR_ALLOW, **kw):
    return C.ingest(raw, received_at=AT, **kw)


def _one(raw=CEDAR_ALLOW, **kw):
    rows = _rows(raw, **kw)
    assert len(rows) == 1
    return rows[0]


def _j(doc) -> bytes:
    return json.dumps(doc).encode()


def _cedar(decision="Allow", reason=("p0",), errors=()) -> bytes:
    return _j({"decision": decision,
               "diagnostics": {"reason": list(reason), "errors": list(errors)}})


def _avp(decision="ALLOW", pols=("SP1",), errors=()) -> bytes:
    return _j({"decision": decision, "determiningPolicies": [{"policyId": p} for p in pols],
               "errors": list(errors)})


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# --- the adapter and its table -------------------------------------------------------------

def test_adapter_is_on_the_one_base_and_registered():
    assert isinstance(C.CEDAR, VendorAdapter) and C.CEDAR.one_row_per_payload is False
    assert adapter_for("cedar") is C.CEDAR
    assert C.CEDAR.name == "cedar" and C.CEDAR.version == "1"


def test_the_table_is_allow_verified_deny_broken():
    assert C.TABLE == {"allow": VERIFIED, "deny": BROKEN}


def test_core_registers_cedar_on_its_own_import_line():
    src = (ROOT / "src" / "arcaeon" / "connector" / "core.py").read_text(encoding="utf-8")
    assert "        from . import cedar  # noqa: F401  (registers itself)\n" in src


# --- the mapping ---------------------------------------------------------------------------

def test_cedar_allow_with_no_errors_is_verified():
    r = _one(CEDAR_ALLOW)
    assert r["kind"] == ROW_KIND and r["relayed"] is True and r["checked_by_us"] is False
    assert "verdict" not in r
    assert r["vendor"] == {"name": "cedar", "adapter_version": "1"}
    assert r["vendor_word"] == "Allow" and r["mapping"] == {"rule": "table"}
    assert r["relayed_verdict"] == VERIFIED and "could_not_look" not in r
    c = r["cedar"]
    assert c["shape"] == "cedar" and c["outcome"] == "allow"
    assert c["policy_ids"] == ["policy0"] and c["policy_ids_total"] == 1
    assert c["errors_reported"] is True and c["errors_count"] == 0
    assert r["received_at"] == AT


def test_cedar_deny_is_broken():
    r = _one(CEDAR_DENY)
    assert r["vendor_word"] == "Deny" and r["relayed_verdict"] == BROKEN
    assert r["cedar"]["outcome"] == "deny" and r["cedar"]["policy_ids"] == ["forbid-contractors"]


@pytest.mark.parametrize("raw", [CEDAR_ERR, AVP_ERR,
                                 _cedar("Deny", errors=["x"]), _avp("ALLOW", errors=[{}])])
def test_any_errors_present_is_could_not_look_whatever_the_decision(raw):
    r = _one(raw)
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["cedar"]["outcome"] == "errored"
    assert r["cedar"]["errors_count"] >= 1
    assert r["cedar"]["errors_digest"].startswith("sha256:jcs:v1:")
    assert r["could_not_look"]["reason_word"] == "unreadable"
    assert "error" in r["could_not_look"]["reason"]


def test_error_text_is_kept_by_digest_only():
    blob = json.dumps(_rows(CEDAR_ERR) + _rows(AVP_ERR))
    assert "attribute not found" not in blob and "errored" in blob
    assert "SPEXAMPLEabcdefg222222" not in blob


@pytest.mark.parametrize("word", ["Permit", "NotApplicable", "", "allowed", "Deny "])
def test_an_unknown_decision_word_is_could_not_look(word):
    r = _one(_cedar(word))
    if word == "Deny ":
        assert r["relayed_verdict"] == BROKEN  # strip + casefold, as the base does
        return
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["mapping"]["rule"] == "unknown_word" and r["vendor_word"] == word
    assert r["cedar"]["outcome"] == "unknown_decision"


@pytest.mark.parametrize("decision", [True, None, 1, ["Allow"], {"Allow": 1}])
def test_a_decision_that_is_not_a_word_is_could_not_look(decision):
    r = _one(_j({"decision": decision, "diagnostics": {"reason": [], "errors": []}}))
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["mapping"]["rule"] == "not_a_word"
    assert r["vendor_word"] is None


def test_case_of_the_decision_word_does_not_matter_but_is_kept():
    assert _one(_cedar("allow"))["relayed_verdict"] == VERIFIED
    assert _one(_avp("ALLOW"))["vendor_word"] == "ALLOW"


# --- Amazon Verified Permissions IsAuthorized ---------------------------------------------

def test_avp_allow_names_its_determining_policy():
    r = _one(AVP_ALLOW)
    assert r["relayed_verdict"] == VERIFIED and r["cedar"]["shape"] == "avp"
    assert r["cedar"]["policy_ids"] == ["SPEXAMPLEabcdefg111111"]
    assert r["policy_ref"]["policy_ids"] == ["SPEXAMPLEabcdefg111111"]


def test_avp_implicit_deny_is_broken_and_said():
    r = _one(AVP_IMPLICIT)
    assert r["relayed_verdict"] == BROKEN
    assert r["cedar"]["implicit_deny"] is True and r["cedar"]["policy_ids"] == []
    assert _one(CEDAR_DENY)["cedar"]["implicit_deny"] is False


def test_avp_capitalised_policy_id_is_read():
    r = _one(AVP_CAP)
    assert r["relayed_verdict"] == VERIFIED
    assert r["cedar"]["policy_ids"] == ["SPEXAMPLEabcdefg333333"]


@pytest.mark.parametrize("doc", [
    {"decision": "ALLOW", "determiningPolicies": [{"policyId": "a"}]},
    {"decision": "Allow", "diagnostics": {"reason": ["a"]}},
])
def test_errors_not_reported_is_could_not_look_even_for_allow(doc):
    r = _one(_j(doc))
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["cedar"]["errors_reported"] is False and r["cedar"]["outcome"] == "errors_not_reported"
    assert r["could_not_look"]["reason_word"] == "missing"


@pytest.mark.parametrize("doc", [
    {"decision": "ALLOW", "determiningPolicies": "SP1", "errors": []},
    {"decision": "ALLOW", "determiningPolicies": [{"policyId": 7}], "errors": []},
    {"decision": "ALLOW", "determiningPolicies": [{"policyId": "a", "PolicyId": "b"}], "errors": []},
    {"decision": "ALLOW", "determiningPolicies": ["SP1"], "errors": []},
    {"decision": "ALLOW", "errors": []},
    {"decision": "ALLOW", "determiningPolicies": [], "errors": "none"},
    {"decision": "Allow", "diagnostics": {"reason": "p0", "errors": []}},
    {"decision": "Allow", "diagnostics": {"reason": [1], "errors": []}},
    {"decision": "Allow", "diagnostics": "ok"},
    {"decision": "Allow", "diagnostics": {"errors": []}},
], ids=["dp_not_list", "pid_not_str", "pid_twice", "dp_item_not_obj", "dp_missing",
        "errors_not_list", "reason_not_list", "reason_item_not_str", "diag_not_obj",
        "reason_missing"])
def test_unreadable_policy_or_error_lists_are_could_not_look(doc):
    r = _one(_j(doc))
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["cedar"]["outcome"] in ("unreadable", "errors_not_reported")


# --- CloudTrail data events (single and batch) ---------------------------------------------

def test_cloudtrail_event_is_read_but_cannot_be_verified():
    r = _one(CT_ONE)
    c = r["cedar"]
    assert c["shape"] == "cloudtrail" and c["event_name"] == "IsAuthorized"
    assert c["event_id"] == "00000000-0000-4000-8000-0000000000e1"
    assert r["vendor_id"] == "00000000-0000-4000-8000-0000000000a1"
    assert r["vendor_word"] == "ALLOW"
    # CloudTrail carries no determiningPolicies and no errors: an ALLOW is not clean
    assert r["relayed_verdict"] == COULD_NOT_LOOK and c["errors_reported"] is False
    assert c["policy_ids"] is None
    assert r["policy_ref"]["policy_store_id"] == "PSEXAMPLEabcdefg111111"
    assert r["policy_ref"]["policy_store_source"] == "payload"
    assert c["request_digest"].startswith("sha256:jcs:v1:")
    assert r["subject"]["sha256"] == c["request_digest"][len("sha256:jcs:v1:"):]
    blob = json.dumps(r)
    assert "user-0001" not in blob and "111122223333" not in blob


def test_cloudtrail_batch_is_one_row_per_result_in_order():
    rows = _rows(CT_BATCH)
    assert len(rows) == 3
    assert [r["cedar"]["item_index"] for r in rows] == [0, 1, 2]
    assert [r["vendor_word"] for r in rows] == ["ALLOW", "DENY", "MAYBE"]
    assert all(r["relayed_verdict"] == COULD_NOT_LOOK for r in rows)
    assert [r["cedar"]["outcome"] for r in rows] == ["errors_not_reported", "errors_not_reported",
                                                    "unknown_decision"]
    assert all(r["cedar"]["event_name"] == "BatchIsAuthorized" for r in rows)
    assert all(r["vendor_id"] == "00000000-0000-4000-8000-0000000000a2" for r in rows)
    digests = {r["cedar"]["request_digest"] for r in rows}
    assert len(digests) == 3


@pytest.mark.parametrize("ad,why", [
    ({"results": []}, "empty"),
    ({"results": "x"}, "name_not_found"),
    ({"decision": "ALLOW", "results": []}, "unreadable"),
    ({}, "name_not_found"),
    ("ALLOW", "name_not_found"),
])
def test_cloudtrail_events_without_a_readable_decision_are_one_row(ad, why):
    r = _one(_j({"eventName": "IsAuthorized", "additionalEventData": ad, "requestID": "q"}))
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["could_not_look"]["reason_word"] == why


def test_a_batch_item_that_is_not_an_object_is_its_own_row():
    raw = _j({"additionalEventData": {"results": [3, {"request": {}, "decision": "DENY"}]}})
    rows = _rows(raw)
    assert [r["cedar"]["item_index"] for r in rows] == [0, 1]
    assert rows[0]["relayed_verdict"] == COULD_NOT_LOOK
    assert rows[0]["could_not_look"]["reason_word"] == "unreadable"


# --- shape detection ----------------------------------------------------------------------

@pytest.mark.parametrize("doc", [
    {"decision": "Allow"},
    {"decision": "Allow", "diagnostics": {"reason": [], "errors": []},
     "determiningPolicies": [], "errors": []},
    {"decision": "ALLOW", "determiningPolicies": [], "errors": [],
     "additionalEventData": {"decision": "ALLOW"}},
    {"hello": "world"},
    {"type": "success", "response": {"decision": "allow",
                                     "diagnostics": {"reason": [], "errors": []}}},
])
def test_no_shape_or_two_shapes_is_one_could_not_look_row(doc):
    r = _one(_j(doc))
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["could_not_look"]["reason_word"] in ("name_not_found", "unreadable")


# --- policy identity ----------------------------------------------------------------------

def test_policy_ref_records_ids_and_leaves_the_join_could_not_look():
    for raw in (CEDAR_ALLOW, CEDAR_DENY, AVP_ALLOW, AVP_IMPLICIT, CT_ONE):
        p = _one(raw)["policy_ref"]
        assert p["join"] == COULD_NOT_LOOK and p["version"] is None
        assert "sealed policy" in p["note"]


def test_a_caller_may_name_the_policy_store_and_it_is_marked_as_the_callers():
    p = _one(AVP_ALLOW, policy_store_id="PSEXAMPLEcaller")["policy_ref"]
    assert p["policy_store_id"] == "PSEXAMPLEcaller" and p["policy_store_source"] == "caller"
    assert _one(AVP_ALLOW)["policy_ref"]["policy_store_id"] is None
    assert _one(AVP_ALLOW)["policy_ref"]["policy_store_source"] is None


def test_a_caller_store_id_that_differs_from_the_event_is_could_not_look():
    r = _one(CT_ONE, policy_store_id="PSEXAMPLEother")
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["policy_ref"]["policy_store_id"] == "PSEXAMPLEabcdefg111111"
    assert "differs" in r["could_not_look"]["reason"]


@pytest.mark.parametrize("bad", ["", 7, ["PS"]])
def test_a_bad_policy_store_argument_is_a_caller_error(bad):
    with pytest.raises(ValueError):
        C.ingest(AVP_ALLOW, policy_store_id=bad)


def test_policy_ids_are_capped_and_counted():
    r = _one(_cedar("Allow", reason=[f"p{i}" for i in range(500)]))
    assert len(r["cedar"]["policy_ids"]) == C.MAX_POLICY_IDS
    assert r["cedar"]["policy_ids_total"] == 500
    assert r["relayed_verdict"] == VERIFIED


# --- unsigned, reported by the sender, sealed once -----------------------------------------

def _every_row_everywhere():
    for raw in ALL_FIXTURES + (b"", b"not json", b"{\"a\": 1, \"a\": 2}", b"x" * 10):
        for r in C.ingest(raw, received_at=AT):
            yield raw, r


def test_every_row_is_unsigned_reported_by_sender_with_the_exact_input_digest():
    n = 0
    for raw, r in _every_row_everywhere():
        n += 1
        assert r["signed_by_vendor"] is False
        assert r["standing"] == "reported_by_sender"
        assert r["input_sha256"] == _sha(raw)
        assert r["vendor_payload_digest"] == "sha256:raw-bytes:v1:" + _sha(raw)
        assert r["attestation"] == {"status": "NONE", "checked_by_us": False, "claimed": None}
    assert n >= 16


def test_signature_looking_fields_change_nothing():
    r = _one(SIGNED_LOOKING)
    assert r["relayed_verdict"] == BROKEN
    assert r["signed_by_vendor"] is False and r["standing"] == "reported_by_sender"
    assert r["attestation"] == {"status": "NONE", "checked_by_us": False, "claimed": None}
    blob = json.dumps(r)
    assert "MEUCIQ" not in blob and "synthetic-key" not in blob


def test_a_signed_looking_allow_is_no_more_than_an_allow():
    doc = json.loads(CEDAR_ALLOW)
    doc.update({"signature": "x" * 200, "signed_by_vendor": True, "standing": "signed"})
    r = _one(_j(doc))
    assert r["relayed_verdict"] == VERIFIED
    assert r["signed_by_vendor"] is False and r["standing"] == "reported_by_sender"


def test_ingest_takes_no_argument_that_can_change_standing():
    params = inspect.signature(C.ingest).parameters
    assert list(params) == ["raw", "received_at", "policy_store_id"]
    for kw in ({"signed_by_vendor": True}, {"standing": "VERIFIED"}, {"verified": True}):
        with pytest.raises(TypeError):
            C.ingest(CEDAR_ALLOW, **kw)  # type: ignore[arg-type]


def test_a_relayed_deny_never_becomes_verified_even_with_a_bad_table(monkeypatch):
    monkeypatch.setitem(C.CEDAR.table, "deny", VERIFIED)
    monkeypatch.setitem(C.CEDAR.table, "permit", VERIFIED)
    for raw in (CEDAR_DENY, AVP_IMPLICIT, SIGNED_LOOKING, _cedar("Permit")):
        r = _one(raw)
        assert r["relayed_verdict"] == COULD_NOT_LOOK
        assert r["signed_by_vendor"] is False


def test_input_sha256_of_a_str_is_of_its_utf8_bytes():
    r = C.ingest(CEDAR_ALLOW.decode("utf-8"), received_at=AT)[0]
    assert r["input_sha256"] == _sha(CEDAR_ALLOW) and r["relayed_verdict"] == VERIFIED


def test_input_sha256_is_of_the_exact_bytes_not_the_parsed_json():
    spaced = b"{ \"decision\" : \"Allow\" , \"diagnostics\": {\"reason\": [\"policy0\"], \"errors\": []} }"
    a, b = _one(CEDAR_ALLOW), _one(spaced)
    assert a["relayed_verdict"] == b["relayed_verdict"] == VERIFIED
    assert a["input_sha256"] != b["input_sha256"] and b["input_sha256"] == _sha(spaced)


def test_never_raises_on_non_bytes():
    r = _one(None)
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["input_sha256"] is None and r["signed_by_vendor"] is False


# --- the rollup is never VERIFIED by itself ------------------------------------------------

def test_rollup_of_all_allow_is_not_verified():
    rows = _rows(CEDAR_ALLOW) + _rows(AVP_ALLOW)
    assert all(r["relayed_verdict"] == VERIFIED for r in rows)
    out = C.rollup(rows)
    assert out["relayed_verdict"] == COULD_NOT_LOOK
    assert out["standing"] == "reported_by_sender" and out["signed_by_vendor"] is False
    assert "verdict" not in out
    assert out["counts"] == {VERIFIED: 2, BROKEN: 0, COULD_NOT_LOOK: 0}


def test_rollup_with_a_relayed_deny_is_broken_never_verified():
    assert C.rollup(_rows(CEDAR_ALLOW) + _rows(CEDAR_DENY))["relayed_verdict"] == BROKEN


@pytest.mark.parametrize("rows", [[], None, "x", [1, None], [{"relayed_verdict": VERIFIED}]])
def test_rollup_of_nothing_or_junk_is_could_not_look(rows):
    assert C.rollup(rows)["relayed_verdict"] == COULD_NOT_LOOK


def test_rollup_ignores_a_row_that_claims_it_was_signed():
    rows = _rows(CEDAR_ALLOW)
    rows[0]["signed_by_vendor"] = True
    rows[0]["standing"] = "VERIFIED"
    assert C.rollup(rows)["relayed_verdict"] == COULD_NOT_LOOK


# --- hostile input: one COULD NOT LOOK row, never a crash ----------------------------------

_DEEP = b"{\"decision\": \"Allow\", \"x\": " + b"[" * 100 + b"]" * 100 + b"}"


@pytest.mark.parametrize("raw,why", [
    (b"", "empty"),
    (b"not json", "unreadable"),
    (b"\xff\xfe\x00junk", "unreadable"),
    (b"{\"decision\": \"Deny\", \"decision\": \"Allow\", \"diagnostics\": "
     b"{\"reason\": [], \"errors\": []}}", "unreadable"),
    (_DEEP, "unreadable"),
    (b"[" * 100000, "unreadable"),
    (b"[]", "name_not_found"),
    (b"[{\"decision\": \"Allow\", \"diagnostics\": {\"reason\": [], \"errors\": []}}]",
     "name_not_found"),
    (b"null", "name_not_found"),
    (b"\"Allow\"", "name_not_found"),
    (b"ALLOW\n", "unreadable"),
], ids=["empty", "not_json", "not_utf8", "dup_key", "too_deep", "deep_brackets", "array",
        "array_of_responses", "null", "bare_string", "cli_text"])
def test_hostile_bodies_are_one_could_not_look_row(raw, why):
    r = _one(raw)
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["could_not_look"]["reason_word"] == why
    assert r["signed_by_vendor"] is False and r["input_sha256"] == _sha(raw)


def test_over_eight_mib_is_digested_not_read():
    raw = b"{" + b" " * C.MAX_PAYLOAD_BYTES + b"}"
    r = _one(raw)
    assert C.MAX_PAYLOAD_BYTES == 8 << 20
    assert r["could_not_look"]["reason_word"] == "bounded"
    assert r["input_sha256"] == _sha(raw) and r["vendor_payload_bytes"] == len(raw)


def test_too_many_batch_results_are_bounded(monkeypatch):
    monkeypatch.setattr(C, "MAX_ROWS", 2)
    items = [{"request": {"i": i}, "decision": "DENY"} for i in range(5)]
    rows = _rows(_j({"additionalEventData": {"results": items}}))
    assert len(rows) == 3 and rows[-1]["could_not_look"]["reason_word"] == "bounded"
    assert all(r["signed_by_vendor"] is False for r in rows)


def test_a_failing_reader_is_one_could_not_look_row(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("synthetic")
    monkeypatch.setattr(C, "_classify", boom)
    r = _one(CEDAR_ALLOW)
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["input_sha256"] == _sha(CEDAR_ALLOW)


def test_long_strings_are_cut():
    r = _one(_cedar("Allow", reason=["p" * 5000]))
    assert len(r["cedar"]["policy_ids"][0]) == MAX_STR


def test_rows_are_json_and_jcs_clean():
    for _, r in _every_row_everywhere():
        json.dumps(r, allow_nan=False)
        C.CEDAR.digest(r)


def test_not_rechecked_or_imported_as_one_verdict():
    r = _one(CEDAR_ALLOW)
    assert recheck(r, CEDAR_ALLOW)["verdict"] == COULD_NOT_LOOK
    assert import_verdict(C.CEDAR, CEDAR_ALLOW)["relayed_verdict"] == COULD_NOT_LOOK
