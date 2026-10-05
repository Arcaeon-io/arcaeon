# SPDX-License-Identifier: MIT
"""L2-05: a Kyverno PolicyReport / ClusterPolicyReport (wgpolicyk8s.io) becomes
relayed check rows on connector.core, one per result. Kyverno does not sign its
reports, so every row is signed_by_vendor false and reported by the sender.
The fixtures are synthetic, shape from the research note, not a live capture.
No network, no cluster."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest

from arcaeon.connector import ROW_KIND, VendorAdapter, adapter_for, import_verdict, recheck
from arcaeon.connector import kyverno as K
from arcaeon.connector.core import MAX_STR
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "kyverno"
POLR = (FIX / "policyreport.json").read_bytes()
CPOLR = (FIX / "clusterpolicyreport.json").read_bytes()
MISMATCH = (FIX / "summary_mismatch.json").read_bytes()
SIGNED_LOOKING = (FIX / "signature_looking.json").read_bytes()
LIST = (FIX / "report_list.json").read_bytes()
ALL_FIXTURES = (POLR, CPOLR, MISMATCH, SIGNED_LOOKING, LIST)
AT = "2026-10-05T12:00:00Z"


def _rows(raw=POLR):
    return K.ingest(raw, received_at=AT)


def _report(results, summary=None, kind="PolicyReport",
             api="wgpolicyk8s.io/v1alpha2") -> bytes:
    doc = {"apiVersion": api, "kind": kind,
           "metadata": {"name": "r", "namespace": "demo", "uid": "u-1", "resourceVersion": "7"},
           "results": results}
    if summary is not None:
        doc["summary"] = summary
    return json.dumps(doc).encode()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# --- the adapter and its table -------------------------------------------------------------

def test_adapter_is_on_the_one_base_and_registered():
    assert isinstance(K.KYVERNO, VendorAdapter) and K.KYVERNO.one_row_per_payload is False
    assert adapter_for("kyverno") is K.KYVERNO
    assert K.KYVERNO.name == "kyverno" and K.KYVERNO.version == "2"


def test_the_table_is_pass_verified_fail_broken_the_rest_could_not_look():
    assert K.TABLE == {"pass": VERIFIED, "fail": BROKEN, "warn": COULD_NOT_LOOK,
                       "error": COULD_NOT_LOOK, "skip": COULD_NOT_LOOK}


# --- one row per result --------------------------------------------------------------------

def test_one_row_per_result_in_order_with_the_documented_fields():
    rows = _rows()
    res = json.loads(POLR)["results"]
    assert len(rows) == len(res) == 5
    for i, (r, e) in enumerate(zip(rows, res)):
        assert r["kind"] == ROW_KIND and r["relayed"] is True and r["checked_by_us"] is False
        assert "verdict" not in r
        assert r["vendor"] == {"name": "kyverno", "adapter_version": "2"}
        assert r["vendor_id"] == "00000000-0000-4000-8000-000000000001"
        assert r["received_at"] == AT
        k = r["kyverno"]
        assert k["result_index"] == i and k["report_index"] == 0
        assert k["policy"] == e["policy"] and k["rule"] == e["rule"]
        assert k["severity"] == e["severity"] and k["category"] == e["category"]
        assert k["source"] == "kyverno" and k["scored"] is e["scored"]
        assert k["timestamp"] == e["timestamp"]
        assert k["resources"] == [{"api_version": x["apiVersion"], "kind": x["kind"],
                                   "namespace": x["namespace"], "name": x["name"],
                                   "uid": x["uid"]} for x in e["resources"]]
        assert k["report"] == {"api_version": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
                               "name": "polr-ns-demo", "namespace": "demo",
                               "uid": "00000000-0000-4000-8000-000000000001",
                               "resource_version": "1001"}
        assert k["summary_check"] == "agrees"


def test_words_map_by_the_table():
    got = [(r["vendor_word"], r["relayed_verdict"], r["mapping"]["rule"]) for r in _rows()]
    assert got == [("pass", VERIFIED, "table"), ("fail", BROKEN, "table"),
                   ("warn", COULD_NOT_LOOK, "table"), ("error", COULD_NOT_LOOK, "table"),
                   ("skip", COULD_NOT_LOOK, "table")]
    for r in _rows()[2:]:
        assert r["could_not_look"]["reason_word"] in ("missing", "unreadable", "name_not_found")


def test_subject_is_the_one_checked_resource():
    r = _rows()[0]
    assert r["subject"] == {"name": "kyverno:demo/Pod/web-0", "sha256": None}


def test_cluster_report_and_a_summary_that_omits_zeroes():
    rows = _rows(CPOLR)
    assert [r["relayed_verdict"] for r in rows] == [VERIFIED, BROKEN]
    k = rows[0]["kyverno"]
    assert k["report"]["kind"] == "ClusterPolicyReport" and k["report"]["namespace"] is None
    assert k["summary_check"] == "agrees"
    assert rows[0]["subject"]["name"] == "kyverno:Namespace/demo"


def test_a_list_of_reports_is_read_report_by_report():
    rows = _rows(LIST)
    assert [(r["kyverno"]["report_index"], r["relayed_verdict"]) for r in rows] == [
        (0, VERIFIED), (1, BROKEN)]
    assert rows[1]["vendor_id"] == "00000000-0000-4000-8000-000000000006"


def test_properties_are_kept_by_digest_only():
    r = _rows()[4]
    props = json.loads(POLR)["results"][4]["properties"]
    assert "properties" not in r["kyverno"]
    assert r["kyverno"]["properties_digest"] == K.KYVERNO.digest(props)
    assert _rows()[0]["kyverno"]["properties_digest"] is None


# --- summary counts ------------------------------------------------------------------------

def test_a_summary_that_disagrees_with_results_is_could_not_look_for_every_row():
    rows = _rows(MISMATCH)
    assert len(rows) == 2
    assert [r["vendor_word"] for r in rows] == ["pass", "fail"]
    for r in rows:
        assert r["relayed_verdict"] == COULD_NOT_LOOK
        assert r["kyverno"]["summary_check"] == "disagrees"
        assert r["could_not_look"]["reason_word"] == "unreadable"
        assert "summary" in r["could_not_look"]["reason"]


@pytest.mark.parametrize("summary", [
    {"pass": True},            # a bool is not a count
    {"pass": "1"},             # a string is not a count
    {"pass": 1, "fail": 1},    # one fail too many
    {"pass": 1.0},             # a float is not a count
    "1 pass",                  # not an object
])
def test_summary_shapes_that_cannot_agree(summary):
    rows = _rows(_report([{"policy": "p", "rule": "r", "result": "pass"}], summary))
    assert rows[0]["relayed_verdict"] == COULD_NOT_LOOK
    assert rows[0]["kyverno"]["summary_check"] == "disagrees"


def test_no_summary_is_said_not_guessed():
    rows = _rows(_report([{"policy": "p", "rule": "r", "result": "pass"}]))
    assert rows[0]["relayed_verdict"] == VERIFIED
    assert rows[0]["kyverno"]["summary_check"] == "absent"


def test_summary_is_counted_over_every_result_even_past_the_row_cap(monkeypatch):
    monkeypatch.setattr(K, "MAX_ROWS", 2)
    res = [{"policy": "p", "rule": "r", "result": "pass"}] * 3
    rows = _rows(_report(res, {"pass": 3}))
    assert len(rows) == 3 and rows[-1]["could_not_look"]["reason_word"] == "bounded"
    assert [r["relayed_verdict"] for r in rows[:2]] == [VERIFIED, VERIFIED]


# --- unsigned, reported by the sender, sealed once -----------------------------------------

def _every_row_everywhere():
    for raw in ALL_FIXTURES + (b"", b"not json", b"{\"a\": 1, \"a\": 2}", b"x" * 10):
        for r in K.ingest(raw, received_at=AT):
            yield raw, r


def test_every_row_is_unsigned_reported_by_sender_with_the_exact_input_digest():
    n = 0
    for raw, r in _every_row_everywhere():
        n += 1
        assert r["signed_by_vendor"] is False
        assert r["standing"] == "reported_by_sender"
        assert r["input_sha256"] == _sha(raw)
        assert r["attestation"]["status"] == "NONE"
        assert r["attestation"]["checked_by_us"] is False
    assert n >= 12


def test_signature_looking_fields_change_nothing():
    rows = _rows(SIGNED_LOOKING)
    assert len(rows) == 1
    r = rows[0]
    assert r["signed_by_vendor"] is False and r["standing"] == "reported_by_sender"
    assert r["attestation"] == {"status": "NONE", "checked_by_us": False, "claimed": None}
    blob = json.dumps(rows)
    assert "MEUCIQ" not in blob and "synthetic-key" not in blob


def test_ingest_takes_no_argument_that_can_change_standing():
    params = inspect.signature(K.ingest).parameters
    assert list(params) == ["raw", "received_at"]
    with pytest.raises(TypeError):
        K.ingest(POLR, signed_by_vendor=True)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        K.ingest(POLR, standing="VERIFIED")  # type: ignore[call-arg]


def test_a_relayed_fail_never_becomes_verified_even_with_a_bad_table(monkeypatch):
    monkeypatch.setitem(K.KYVERNO.table, "fail", VERIFIED)
    monkeypatch.setitem(K.KYVERNO.table, "warn", VERIFIED)
    rows = _rows()
    assert [r["relayed_verdict"] for r in rows] == [VERIFIED, COULD_NOT_LOOK, COULD_NOT_LOOK,
                                                    COULD_NOT_LOOK, COULD_NOT_LOOK]


def test_input_sha256_of_a_str_is_of_its_utf8_bytes():
    text = POLR.decode("utf-8")
    rows = K.ingest(text, received_at=AT)
    assert rows[0]["input_sha256"] == _sha(POLR)
    assert [r["relayed_verdict"] for r in rows] == [r["relayed_verdict"] for r in _rows()]


def test_never_raises_on_non_bytes():
    rows = K.ingest(None, received_at=AT)
    assert len(rows) == 1 and rows[0]["relayed_verdict"] == COULD_NOT_LOOK
    assert rows[0]["input_sha256"] is None and rows[0]["signed_by_vendor"] is False


# --- policy identity ----------------------------------------------------------------------

def test_policy_ref_names_the_policy_and_leaves_the_join_could_not_look():
    for r in _rows():
        p = r["policy_ref"]
        assert p["policy"] == r["kyverno"]["policy"] and p["rule"] == r["kyverno"]["rule"]
        assert p["version"] is None
        assert p["join"] == COULD_NOT_LOOK
        assert "no policy version" in p["note"]


# --- the rollup is never VERIFIED by itself ------------------------------------------------

def test_rollup_of_all_pass_is_not_verified():
    rows = _rows(_report([{"policy": "p", "rule": "r", "result": "pass"}] * 2, {"pass": 2}))
    assert all(r["relayed_verdict"] == VERIFIED for r in rows)
    out = K.rollup(rows)
    assert out["relayed_verdict"] == COULD_NOT_LOOK
    assert out["standing"] == "reported_by_sender" and out["signed_by_vendor"] is False
    assert "verdict" not in out
    assert out["counts"] == {VERIFIED: 2, BROKEN: 0, COULD_NOT_LOOK: 0}


def test_rollup_with_a_relayed_fail_is_broken_never_verified():
    out = K.rollup(_rows())
    assert out["relayed_verdict"] == BROKEN


@pytest.mark.parametrize("rows", [[], None, "x", [1, None], [{"relayed_verdict": VERIFIED}]])
def test_rollup_of_nothing_or_junk_is_could_not_look(rows):
    assert K.rollup(rows)["relayed_verdict"] == COULD_NOT_LOOK


def test_rollup_ignores_a_row_that_claims_it_was_signed():
    rows = _rows(_report([{"policy": "p", "rule": "r", "result": "pass"}]))
    rows[0]["signed_by_vendor"] = True
    rows[0]["standing"] = "VERIFIED"
    assert K.rollup(rows)["relayed_verdict"] == COULD_NOT_LOOK


# --- hostile input: one COULD NOT LOOK row, never a crash ----------------------------------

_DEEP = (b"{\"apiVersion\": \"wgpolicyk8s.io/v1alpha2\", \"kind\": \"PolicyReport\", \"x\": "
         + b"[" * 100 + b"]" * 100 + b"}")


@pytest.mark.parametrize("raw,why", [
    (b"", "empty"),
    (b"not json", "unreadable"),
    (b"\xff\xfe\x00junk", "unreadable"),
    (b"{\"kind\": \"PolicyReport\", \"kind\": \"ClusterPolicyReport\"}", "unreadable"),
    (_DEEP, "unreadable"),
    (b"[" * 100000, "unreadable"),
    (b"[]", "name_not_found"),
    (b"null", "name_not_found"),
    (b"{\"kind\": \"Pod\", \"apiVersion\": \"v1\"}", "name_not_found"),
    (b"{\"kind\": \"PolicyReport\", \"apiVersion\": \"example.com/v1\", \"results\": []}",
     "name_not_found"),
    (b"POLICY  RULE  RESULT\nrequire-labels  check  pass\n", "unreadable"),
    (b"{\"kind\": \"List\", \"apiVersion\": \"v1\", \"items\": []}", "empty"),
    (b"{\"kind\": \"List\", \"apiVersion\": \"v1\", \"items\": 3}", "name_not_found"),
], ids=["empty", "not_json", "not_utf8", "dup_key", "too_deep", "deep_brackets", "array",
        "null", "not_a_report", "unknown_api", "cli_text", "empty_list", "items_not_list"])
def test_hostile_bodies_are_one_could_not_look_row(raw, why):
    rows = K.ingest(raw, received_at=AT)
    assert len(rows) == 1
    r = rows[0]
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["could_not_look"]["reason_word"] == why
    assert r["signed_by_vendor"] is False and r["input_sha256"] == _sha(raw)
    assert r["vendor_payload_digest"] == "sha256:raw-bytes:v1:" + _sha(raw)


@pytest.mark.parametrize("results,why", [
    ([], "empty"),
    (None, "missing"),
    ("pass", "name_not_found"),
])
def test_a_report_with_no_readable_results_is_one_row(results, why):
    rows = _rows(_report(results))
    assert len(rows) == 1 and rows[0]["relayed_verdict"] == COULD_NOT_LOOK
    assert rows[0]["could_not_look"]["reason_word"] == why


def test_a_list_item_that_is_not_a_report_is_its_own_row():
    good = json.loads(_report([{"policy": "p", "rule": "r", "result": "pass"}]))
    raw = json.dumps({"apiVersion": "v1", "kind": "List", "items": [1, good]}).encode()
    rows = _rows(raw)
    assert [r["relayed_verdict"] for r in rows] == [COULD_NOT_LOOK, VERIFIED]
    assert rows[0]["kyverno"]["report_index"] == 0


def test_over_eight_mib_is_digested_not_read():
    raw = b"{" + b" " * (K.MAX_PAYLOAD_BYTES) + b"}"
    rows = K.ingest(raw, received_at=AT)
    assert K.MAX_PAYLOAD_BYTES == 8 << 20
    assert len(rows) == 1 and rows[0]["could_not_look"]["reason_word"] == "bounded"
    assert rows[0]["input_sha256"] == _sha(raw)
    assert rows[0]["vendor_payload_bytes"] == len(raw)


@pytest.mark.parametrize("res,word,rule", [
    ({"policy": "p", "rule": "r", "result": "passed"}, "passed", "unknown_word"),
    ({"policy": "p", "rule": "r", "result": True}, None, "not_a_word"),
    ({"policy": "p", "rule": "r"}, None, "not_a_word"),
    ({"policy": "p", "rule": "r", "result": ["pass"]}, None, "not_a_word"),
    ({"policy": "p", "rule": "r", "result": {"pass": 1}}, None, "not_a_word"),
])
def test_an_unknown_or_missing_result_word_is_could_not_look(res, word, rule):
    rows = _rows(_report([res], {"pass": 0}))
    assert len(rows) == 1
    r = rows[0]
    assert r["vendor_word"] == word and r["mapping"]["rule"] == rule
    assert r["kyverno"]["summary_check"] == "agrees"
    assert r["relayed_verdict"] == COULD_NOT_LOOK and "could_not_look" in r


def test_a_result_that_is_not_an_object_is_its_own_row():
    rows = _rows(_report([7, {"policy": "p", "rule": "r", "result": "fail"}]))
    assert [r["relayed_verdict"] for r in rows] == [COULD_NOT_LOOK, BROKEN]
    assert rows[0]["kyverno"]["result_index"] == 0


def test_too_many_results_are_bounded(monkeypatch):
    monkeypatch.setattr(K, "MAX_ROWS", 2)
    rows = _rows(_report([{"policy": "p", "rule": "r", "result": "fail"}] * 5))
    assert len(rows) == 3 and rows[-1]["could_not_look"]["reason_word"] == "bounded"
    assert all(r["signed_by_vendor"] is False for r in rows)


def test_long_strings_are_cut_and_resources_are_capped():
    res = {"policy": "p" * 1000, "rule": "r", "result": "pass", "message": "m" * 5000,
           "resources": [{"kind": "Pod", "name": f"x{i}"} for i in range(500)]}
    r = _rows(_report([res]))[0]
    assert len(r["kyverno"]["policy"]) == MAX_STR and len(r["kyverno"]["message"]) == MAX_STR
    assert len(r["kyverno"]["resources"]) == K.MAX_RESOURCES
    assert r["kyverno"]["resources_total"] == 500
    assert r["subject"] is None


def test_rows_are_json_and_jcs_clean():
    for _, r in _every_row_everywhere():
        json.dumps(r, allow_nan=False)
        K.KYVERNO.digest(r)


def test_not_rechecked_or_imported_as_one_verdict():
    rows = _rows()
    assert recheck(rows[0], POLR)["verdict"] == COULD_NOT_LOOK
    one = import_verdict(K.KYVERNO, POLR)
    assert one["relayed_verdict"] == COULD_NOT_LOOK
