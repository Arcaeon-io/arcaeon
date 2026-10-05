# SPDX-License-Identifier: MIT
"""L2-03: Lakera Guard API v2 screening responses become relayed check rows on
connector.core: one row for the response, plus one per detector hit and per
payload match span. The fixtures are synthetic, shaped from R15, not a live
capture. No network.

R15: Lakera does not sign its responses, so every row says
`signed_by_vendor: false` and is reported by sender; such rows alone never make
a VERIFIED (T4), and a relayed BROKEN never turns into VERIFIED (stack review F12).
`flagged` is always false in Detect mode, so "not flagged" relays VERIFIED only
when the caller declares the policy runs in Enforce mode."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest

from arcaeon.connector import ROW_KIND, VendorAdapter, adapter_for, import_verdict, recheck
from arcaeon.connector import lakera_guard as L
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "lakera_guard"
FLAGGED = (FIX / "flagged.json").read_bytes()
CLEAN = (FIX / "clean.json").read_bytes()
DETECT = (FIX / "detect_mode.json").read_bytes()
RESULTS = (FIX / "results_endpoint.json").read_bytes()
AT = "2026-10-05T12:00:00Z"
UUID1 = "00000000-0000-4000-8000-000000000001"


def _rows(raw, **kw):
    return L.ingest(raw, received_at=AT, **kw)


def _summary(rows):
    return [(r["vendor_word"], r["relayed_verdict"]) for r in rows]


def _mutate(raw, fn):
    doc = json.loads(raw)
    fn(doc)
    return json.dumps(doc).encode()


# ------------------------------------------------------------------ the base

def test_adapter_is_on_the_one_base_and_registered():
    assert isinstance(L.LAKERA_GUARD, VendorAdapter)
    assert L.LAKERA_GUARD.one_row_per_payload is False
    assert adapter_for("lakera-guard") is L.LAKERA_GUARD
    assert L.LAKERA_GUARD.version == "1"
    assert L.MAX_PAYLOAD_BYTES == 8 << 20


def test_table_maps_only_into_our_three_words_and_only_not_flagged_is_verified():
    assert set(L.TABLE.values()) <= {VERIFIED, BROKEN, COULD_NOT_LOOK}
    assert [w for w, v in L.TABLE.items() if v == VERIFIED] == ["not_flagged"]
    assert sorted(w for w, v in L.TABLE.items() if v == BROKEN) == [
        "detector_detected", "flagged", "payload_match"]


# ------------------------------------------------------------------ not flagged

def test_not_flagged_in_declared_enforce_mode_relays_verified_for_that_row():
    rows = _rows(CLEAN, policy_mode="enforce")
    assert _summary(rows) == [("not_flagged", VERIFIED)]
    r = rows[0]
    assert r["kind"] == ROW_KIND and r["relayed"] is True and r["checked_by_us"] is False
    assert "verdict" not in r and "could_not_look" not in r
    assert r["vendor"] == {"name": "lakera-guard", "adapter_version": "1"}
    assert r["received_at"] == AT
    f = r["finding"]
    assert f["part"] == "response" and f["flagged"] is False and f["policy_mode"] == "enforce"
    assert f["detectors_reported"] == 2 and f["detectors_detected"] == 0
    assert f["payload_matches"] == 0


def test_not_flagged_without_a_declared_mode_is_could_not_look():
    rows = _rows(CLEAN)
    assert _summary(rows) == [("not_flagged_mode_undeclared", COULD_NOT_LOOK)]
    assert rows[0]["could_not_look"]["reason_word"] == "name_not_found"


def test_not_flagged_in_detect_mode_is_could_not_look():
    rows = _rows(CLEAN, policy_mode="detect")
    assert _summary(rows) == [("not_flagged_detect_mode", COULD_NOT_LOOK)]


def test_detect_mode_detection_is_broken_and_blocks_the_clean_row():
    for mode in (None, "detect", "enforce"):
        rows = _rows(DETECT, policy_mode=mode)
        assert _summary(rows) == [("not_flagged_unsettled", COULD_NOT_LOOK),
                                  ("detector_detected", BROKEN)]
        assert rows[1]["finding"]["detector_type"] == "prompt_attack"
        assert rows[1]["finding"]["message_id"] == 1


@pytest.mark.parametrize("bad", ["Enforce", "monitor", 1, True])
def test_a_bad_policy_mode_is_a_caller_error(bad):
    with pytest.raises(ValueError):
        L.ingest(CLEAN, policy_mode=bad)


# ------------------------------------------------------------------ flagged

def test_flagged_gives_broken_rows_per_detector_hit_and_match():
    rows = _rows(FLAGGED, policy_mode="enforce")
    assert _summary(rows) == [("flagged", BROKEN), ("detector_detected", BROKEN),
                              ("detector_detected", BROKEN), ("payload_match", BROKEN)]
    resp, d1, d2, m = rows
    assert resp["finding"]["action"] == "enforce"
    assert resp["finding"]["detectors_reported"] == 3
    assert resp["finding"]["detectors_detected"] == 2
    assert resp["finding"]["payload_matches"] == 1
    assert resp["finding"]["model_version"] == "synthetic-model"
    assert [d1["finding"]["detector_type"], d2["finding"]["detector_type"]] == [
        "prompt_attack", "pii/email"]
    assert d1["finding"]["result"] == "l1_confident"
    assert d1["finding"]["detector_id"] == "detector-synthetic-a"
    assert d1["finding"]["index"] == 0 and d2["finding"]["index"] == 1
    assert m["finding"]["part"] == "payload" and m["finding"]["labels"] == ["synthetic-label"]
    assert (m["finding"]["start"], m["finding"]["end"]) == (11, 27)


def test_flagged_is_broken_whatever_mode_the_caller_declares():
    for mode in (None, "detect", "enforce"):
        assert _rows(FLAGGED, policy_mode=mode)[0]["relayed_verdict"] == BROKEN


def test_match_text_is_kept_by_digest_only():
    rows = _rows(FLAGGED)
    assert "synthetic match text" not in json.dumps(rows)
    assert rows[-1]["finding"]["text_digest"] == L.LAKERA_GUARD.digest("synthetic match text")


def test_flagged_not_a_boolean_is_could_not_look():
    for v in ("true", 1, None):
        raw = _mutate(CLEAN, lambda d: d.__setitem__("flagged", v))
        rows = _rows(raw, policy_mode="enforce")
        assert _summary(rows)[0] == ("flagged_unreadable", COULD_NOT_LOOK)
        assert VERIFIED not in [r["relayed_verdict"] for r in rows]


def test_an_unreadable_breakdown_entry_blocks_the_clean_row():
    raw = _mutate(CLEAN, lambda d: d["breakdown"].append({"detector_type": "x",
                                                          "detected": "yes"}))
    rows = _rows(raw, policy_mode="enforce")
    assert _summary(rows) == [("not_flagged_unsettled", COULD_NOT_LOOK),
                              ("detector_unreadable", COULD_NOT_LOOK)]
    raw = _mutate(CLEAN, lambda d: d.__setitem__("payload", "oops"))
    rows = _rows(raw, policy_mode="enforce")
    assert _summary(rows) == [("not_flagged_unsettled", COULD_NOT_LOOK),
                              ("payload_unreadable", COULD_NOT_LOOK)]


def test_a_payload_match_without_flag_is_broken():
    raw = _mutate(CLEAN, lambda d: d.__setitem__("payload", [
        {"start": 0, "end": 3, "text": "abc", "detector_type": "pii/email", "labels": [],
         "message_id": 0}]))
    rows = _rows(raw, policy_mode="enforce")
    assert _summary(rows) == [("not_flagged_unsettled", COULD_NOT_LOOK),
                              ("payload_match", BROKEN)]


def test_the_results_endpoint_is_not_a_screening_result():
    rows = _rows(RESULTS, policy_mode="enforce")
    assert _summary(rows) == [("results_not_screening", COULD_NOT_LOOK)]


# ------------------------------------------------------------------ R15: unsigned, always

def test_every_row_says_signed_by_vendor_false_and_reported_by_sender():
    for raw in (FLAGGED, CLEAN, DETECT, RESULTS, b"", b"not json", b"[]", None):
        for mode in (None, "enforce"):
            for r in _rows(raw, policy_mode=mode):
                assert r["signed_by_vendor"] is False
                assert r["standing"] == "reported_by_sender"
                assert r["attestation"]["status"] == "NONE"
                assert r["attestation"]["claimed"] is None


def test_a_signature_looking_field_still_yields_false():
    def sign(d):
        d["signature"] = {"alg": "ed25519", "kid": "lakera-1", "sig": "A" * 128}
        d["signed"] = True
        d["signed_by_vendor"] = True
        d["standing"] = "verified_by_vendor"
        d["attestation"] = {"status": "VERIFIED", "signature": "B" * 88}
        d["metadata"]["signature"] = "C" * 88
        d["breakdown"][0]["signature"] = "D" * 88
    for raw in (CLEAN, FLAGGED):
        rows = _rows(_mutate(raw, sign), policy_mode="enforce")
        assert rows and all(r["signed_by_vendor"] is False for r in rows)
        assert all(r["standing"] == "reported_by_sender" for r in rows)
        assert all(r["attestation"]["status"] == "NONE" for r in rows)
        assert L.standing_verdict(rows)["verdict"] != VERIFIED


def test_no_parameter_can_set_signed_by_vendor_or_standing():
    params = inspect.signature(L.ingest).parameters
    assert not [p for p in params if any(w in p.lower() for w in ("sign", "attest", "stand"))]
    with pytest.raises(TypeError):
        L.ingest(CLEAN, signed_by_vendor=True)
    with pytest.raises(TypeError):
        L.ingest(CLEAN, standing="verified")


# ------------------------------------------------------------------ T4 / F12

def test_unsigned_rows_alone_never_make_verified():
    rows = _rows(CLEAN, policy_mode="enforce")
    assert all(r["relayed_verdict"] == VERIFIED for r in rows)
    got = L.standing_verdict(rows)
    assert got["verdict"] == COULD_NOT_LOOK
    assert got["relayed_verdict"] == VERIFIED and got["signed_by_vendor"] is False
    assert got["standing"] == "reported_by_sender"


def test_a_relayed_broken_is_broken_never_verified():
    rows = _rows(FLAGGED)
    got = L.standing_verdict(rows)
    assert got["verdict"] == BROKEN and got["relayed_verdict"] == BROKEN
    mixed = rows[:1] + _rows(CLEAN, policy_mode="enforce")
    assert L.standing_verdict(mixed)["verdict"] == BROKEN


def test_a_relayed_broken_row_edited_to_say_signed_is_still_broken():
    row = _rows(FLAGGED)[0]
    row["signed_by_vendor"] = True
    row["standing"] = "verified_by_vendor"
    row["attestation"] = {"status": "VERIFIED", "checked_by_us": True, "claimed": {}}
    assert L.standing_verdict([row])["verdict"] == BROKEN


def test_standing_verdict_on_nothing_or_other_vendors_is_could_not_look():
    for rows in ([], None, "rows", [{"kind": "x"}],
                 [{"vendor": {"name": "snyk-agent-scan"}, "relayed_verdict": VERIFIED}]):
        assert L.standing_verdict(rows)["verdict"] == COULD_NOT_LOOK


# ------------------------------------------------------------------ digests and ids

def test_input_sha256_is_over_the_exact_bytes_read():
    for raw in (FLAGGED, CLEAN, DETECT, b"not json", CLEAN + b"\n"):
        want = hashlib.sha256(raw).hexdigest()
        for r in _rows(raw):
            assert r["input_sha256"] == want
            assert r["vendor_payload_digest"].endswith(want)
            assert r["vendor_payload_bytes"] == len(raw)
    assert _rows(CLEAN)[0]["input_sha256"] != _rows(CLEAN + b" ")[0]["input_sha256"]


def test_str_input_is_hashed_as_its_utf8_bytes():
    assert _rows(CLEAN.decode("utf-8"))[0]["input_sha256"] == hashlib.sha256(CLEAN).hexdigest()


def test_request_body_is_digested_when_given():
    body = b'{"messages": [{"role": "user", "content": "synthetic"}]}'
    r = _rows(CLEAN, request_body=body)[0]
    assert r["request_sha256"] == hashlib.sha256(body).hexdigest()
    assert r["subject"]["sha256"] == hashlib.sha256(body).hexdigest()
    assert "synthetic\"" not in json.dumps(r)
    assert _rows(CLEAN)[0]["request_sha256"] is None
    with pytest.raises(ValueError):
        L.ingest(CLEAN, request_body=42)


def test_vendor_request_id_from_the_response_first():
    rows = _rows(FLAGGED, vendor_request_id="caller-synthetic-0001")
    for r in rows:
        assert r["vendor_request_id"] == UUID1 and r["vendor_id"] == UUID1
        assert r["vendor_request_id_source"] == "response"
        assert r["ids"] == {"request_uuid": UUID1, "caller": "caller-synthetic-0001"}


def test_vendor_request_id_from_the_caller_else_null():
    no_uuid = _mutate(CLEAN, lambda d: d.pop("metadata"))
    r = _rows(no_uuid, vendor_request_id="caller-synthetic-0001")[0]
    assert r["vendor_request_id"] == "caller-synthetic-0001"
    assert r["vendor_request_id_source"] == "caller"
    r = _rows(no_uuid)[0]
    assert r["vendor_request_id"] is None and r["vendor_request_id_source"] is None
    assert _rows(no_uuid, vendor_request_id=42)[0]["vendor_request_id"] is None
    bad = _mutate(CLEAN, lambda d: d["metadata"].__setitem__("request_uuid", 7))
    assert _rows(bad)[0]["vendor_request_id"] is None
    r = _rows(b"not json", vendor_request_id="caller-synthetic-0002")[0]
    assert r["vendor_request_id"] == "caller-synthetic-0002"


# ------------------------------------------------------------------ hostile input

@pytest.mark.parametrize("raw,why", [
    (b"", "empty"),
    (b"not json", "unreadable"),
    (b"{\"flagged\": ", "unreadable"),
    (b"\xff\xfe\x00garbage", "unreadable"),
    (b"{\"flagged\": true, \"flagged\": false}", "unreadable"),
    (b"[]", "name_not_found"),
    (b"{\"anything\": true}", "name_not_found"),
    (b"[" * 200 + b"]" * 200, "unreadable"),
    (b"{\"flagged\": false, \"metadata\": " + b"{\"a\": " * 100 + b"1" + b"}" * 101,
     "unreadable"),
])
def test_malformed_input_is_one_could_not_look_row_never_a_crash(raw, why):
    rows = _rows(raw, policy_mode="enforce")
    assert len(rows) == 1
    assert rows[0]["relayed_verdict"] == COULD_NOT_LOOK
    assert rows[0]["could_not_look"]["reason_word"] == why
    assert rows[0]["signed_by_vendor"] is False


def test_never_raises_on_non_bytes():
    for raw in (None, 7, ["x"]):
        rows = _rows(raw)
        assert len(rows) == 1 and rows[0]["relayed_verdict"] == COULD_NOT_LOOK
        assert rows[0]["input_sha256"] is None and rows[0]["signed_by_vendor"] is False


def test_oversized_input_is_bounded_and_still_digested():
    big = b" " * (L.MAX_PAYLOAD_BYTES + 1)
    rows = _rows(big)
    assert len(rows) == 1 and rows[0]["could_not_look"]["reason_word"] == "bounded"
    assert rows[0]["input_sha256"] == hashlib.sha256(big).hexdigest()


def test_too_many_rows_are_bounded(monkeypatch):
    monkeypatch.setattr(L, "MAX_ROWS", 2)
    rows = _rows(FLAGGED)
    assert len(rows) == 3 and rows[-1]["could_not_look"]["reason_word"] == "bounded"


def test_garbage_entries_are_their_own_rows():
    doc = {"flagged": True, "breakdown": [7, {"detected": True}], "payload": ["x"]}
    rows = _rows(json.dumps(doc).encode())
    assert _summary(rows) == [("flagged", BROKEN), ("detector_unreadable", COULD_NOT_LOOK),
                              ("detector_detected", BROKEN),
                              ("payload_unreadable", COULD_NOT_LOOK)]


def test_long_strings_are_cut():
    raw = _mutate(FLAGGED, lambda d: d["breakdown"][0].__setitem__("detector_type", "n" * 5000))
    assert len(_rows(raw)[1]["finding"]["detector_type"]) == 256


def test_not_rechecked_or_imported_as_one_verdict():
    rows = _rows(CLEAN, policy_mode="enforce")
    assert recheck(rows[0], CLEAN)["verdict"] == COULD_NOT_LOOK
    assert import_verdict(L.LAKERA_GUARD, CLEAN)["relayed_verdict"] == COULD_NOT_LOOK


def test_the_doc_states_the_mapping_table_and_its_limits():
    doc = (ROOT / "docs" / "CONNECTOR_ADAPTER.md").read_text(encoding="utf-8")
    body = doc[doc.index("## Lakera Guard"):]
    body = body[:body.index("\n## ", 5)]
    for word, ours in L.TABLE.items():
        assert f"| `{word}` | {ours} |" in body, word
    assert "### What this cannot prove" in body
    assert "signed_by_vendor: false" in body
    for phrase in ("tamper-proof", "guarantee", "—", "–"):
        assert phrase not in body.lower(), phrase
