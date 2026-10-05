# SPDX-License-Identifier: MIT
"""L2-08: HiddenLayer alerts (webhook data sources: runtime security convictions,
supply chain scans, runtime policy outcomes) become relayed check.verdict rows,
one per alert, always unsigned, always reported_by_sender. Fixtures are shaped
from the public docs (tests/fixtures/hiddenlayer/README.md), not a live capture.
No network."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest

from arcaeon.connector import ROW_KIND, VendorAdapter, adapter_for, recheck
from arcaeon.connector import hiddenlayer as H
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "hiddenlayer"
CONV = (FIX / "conviction.json").read_bytes()
SCAN = (FIX / "supply_chain_scan.json").read_bytes()
CLEAN = (FIX / "supply_chain_scan_clean.json").read_bytes()
RPO = (FIX / "policy_outcome.json").read_bytes()
AUDIT = (FIX / "audit_log.json").read_bytes()
AT = "2026-10-05T12:00:00Z"


def _ing(raw):
    return H.ingest(raw, received_at=AT)


def _one(raw):
    rows = _ing(raw)
    assert len(rows) == 1, rows
    return rows[0]


def _doc(raw):
    return json.loads(raw)


def _b(doc):
    return json.dumps(doc).encode()


def _sealed(r, raw=None):
    assert r["signed_by_vendor"] is False
    assert r["standing"] == "reported_by_sender"
    assert r["attestation"] == {"status": "NONE", "checked_by_us": False, "claimed": None}
    assert r["vendor"] == {"name": "hiddenlayer", "adapter_version": "1"}
    assert r["kind"] == ROW_KIND and r["relayed"] is True and r["checked_by_us"] is False
    assert r["relayed_verdict"] in (VERIFIED, BROKEN, COULD_NOT_LOOK)
    assert "verdict" not in r
    if isinstance(raw, (bytes, bytearray)):
        assert r["input_sha256"] == hashlib.sha256(raw).hexdigest()


# --- the adapter ---------------------------------------------------------------

def test_adapter_is_on_the_one_base_and_registered():
    assert isinstance(H.HIDDENLAYER, VendorAdapter) and H.HIDDENLAYER.one_row_per_payload is False
    assert adapter_for("hiddenlayer") is H.HIDDENLAYER
    assert H.STANDING == "reported_by_sender"


def test_every_other_adapter_still_registered():
    for name in ("mockscan", "opa", "mcp-scan", "reported", "hiddenlayer"):
        assert adapter_for(name) is not None, name


def test_ingest_takes_no_argument_that_could_sign():
    params = set(inspect.signature(H.ingest).parameters)
    assert params == {"raw", "received_at"}


# --- the documented shapes -----------------------------------------------------

def test_conviction_is_broken():
    r = _one(CONV)
    _sealed(r, CONV)
    assert r["relayed_verdict"] == BROKEN and r["vendor_word"] == "conviction"
    a = r["alert"]
    assert a["source"] == "runtime_security_conviction"
    assert a["id"] == "b53bc9c8-e5cc-4bd8-a3bf-98576de4cb71"
    assert r["vendor_id"] == r["vendor_request_id"] == a["id"]
    assert a["severity"] == "low" and a["detection_category"] == "Guardrail Activation"
    assert a["mitre_technique"] == "AML.T0048"
    assert r["subject"]["name"].startswith("hiddenlayer:runtime_security_conviction/")
    assert "could_not_look" not in r


def test_conviction_copies_no_requester_or_tenant():
    text = json.dumps(_one(CONV))
    assert "gpburdell" not in text and "b2774567" not in text


def test_scan_with_detections_is_broken():
    r = _one(SCAN)
    _sealed(r, SCAN)
    assert r["relayed_verdict"] == BROKEN and r["vendor_word"] == "scan_detections"
    a = r["alert"]
    assert a["source"] == "supply_chain_scan" and a["status"] == "done"
    assert a["detection_count"] == 3 and a["severity"] == "high"
    assert a["id"] == "3246d37b-b211-4983-80a8-86851c484fa8"
    assert "gpburdell" not in json.dumps(r)


def test_scan_clean_is_verified_only_when_every_count_says_so():
    r = _one(CLEAN)
    _sealed(r, CLEAN)
    assert r["relayed_verdict"] == VERIFIED and r["vendor_word"] == "scan_clean"
    assert "could_not_look" not in r


@pytest.mark.parametrize("path,value", [
    (("summary", "files_failed_to_scan"), 1),
    (("summary", "unknown_files"), 2),
    (("summary", "files_failed_to_scan"), None),
    (("summary", "detection_count"), 1),
    (("scan_error",), "boom"),
    (("file_count",), 0),
    (("detection_count",), "0"),
    (("detection_count",), False),
    (("severity",), "low"),
])
def test_scan_clean_with_any_gap_is_could_not_look(path, value):
    doc = _doc(CLEAN)
    node = doc["scan_result_summary"]
    for k in path[:-1]:
        node = node[k]
    if value is None:
        node.pop(path[-1])
    else:
        node[path[-1]] = value
    raw = _b(doc)
    r = _one(raw)
    _sealed(r, raw)
    assert r["relayed_verdict"] == COULD_NOT_LOOK, (path, value, r["vendor_word"])
    assert "could_not_look" in r


def test_scan_missing_summary_block_is_not_clean():
    doc = _doc(CLEAN)
    doc["scan_result_summary"].pop("summary")
    assert _one(_b(doc))["relayed_verdict"] == COULD_NOT_LOOK


@pytest.mark.parametrize("status", ["running", "failed", "", None, 3, "DONEISH"])
def test_scan_unknown_status_is_could_not_look(status):
    doc = _doc(SCAN)
    doc["scan_result_summary"]["status"] = status
    r = _one(_b(doc))
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["vendor_word"] == "unknown_status"


def test_scan_status_is_casefolded():
    doc = _doc(SCAN)
    doc["scan_result_summary"]["status"] = " Done "
    assert _one(_b(doc))["relayed_verdict"] == BROKEN


@pytest.mark.parametrize("sev", ["critical", "severe", "", None, 5])
def test_scan_detection_unknown_severity_is_could_not_look(sev):
    doc = _doc(SCAN)
    doc["scan_result_summary"]["severity"] = sev
    r = _one(_b(doc))
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["vendor_word"] == "unknown_severity"


@pytest.mark.parametrize("sev", ["critical", "Bad", "", None, 1, ["Low"]])
def test_conviction_unknown_severity_is_could_not_look(sev):
    doc = _doc(CONV)
    doc["severity"] = sev
    r = _one(_b(doc))
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["vendor_word"] == "unknown_severity"


@pytest.mark.parametrize("sev", ["Low", "MEDIUM", "high"])
def test_conviction_known_severity_is_broken(sev):
    doc = _doc(CONV)
    doc["severity"] = sev
    assert _one(_b(doc))["relayed_verdict"] == BROKEN


def test_policy_block_is_broken():
    r = _one(RPO)
    _sealed(r, RPO)
    assert r["relayed_verdict"] == BROKEN and r["vendor_word"] == "policy_block"
    a = r["alert"]
    assert a["source"] == "runtime_policy_outcome"
    assert a["action"] == "BLOCK" and a["threat_level"] == "HIGH"
    assert a["detection_names"] == ["prompt_injection"]
    assert a["id"] == "0c7fe87b-9bc6-4651-bf2c-80f8376817d1"
    assert "gpburdell" not in json.dumps(r) and "sess-abc-123" not in json.dumps(r)


@pytest.mark.parametrize("action,word", [("DETECT", "policy_detect"), ("redact", "policy_redact")])
def test_policy_detect_and_redact_with_a_detection_are_broken(action, word):
    doc = _doc(RPO)
    doc["evaluation"]["action"] = action
    r = _one(_b(doc))
    assert r["relayed_verdict"] == BROKEN and r["vendor_word"] == word


@pytest.mark.parametrize("action", ["DETECT", "REDACT"])
def test_policy_action_with_no_detection_is_could_not_look(action):
    doc = _doc(RPO)
    doc["evaluation"] = {"action": action, "highest_threat_level": "NONE"}
    doc["detections"] = []
    r = _one(_b(doc))
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["vendor_word"] == "policy_action_without_detection"


def test_policy_block_with_no_detection_still_broken():
    doc = _doc(RPO)
    doc["evaluation"]["highest_threat_level"] = "NONE"
    doc["detections"] = []
    assert _one(_b(doc))["relayed_verdict"] == BROKEN


@pytest.mark.parametrize("action", ["NONE", "ALLOW", "", None, 1])
def test_policy_unknown_action_is_could_not_look(action):
    doc = _doc(RPO)
    doc["evaluation"]["action"] = action
    r = _one(_b(doc))
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["vendor_word"] == "unknown_action"


@pytest.mark.parametrize("lvl", ["SEVERE", "", None, 3])
def test_policy_unknown_threat_level_is_could_not_look(lvl):
    doc = _doc(RPO)
    doc["evaluation"]["highest_threat_level"] = lvl
    r = _one(_b(doc))
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["vendor_word"] == "unknown_severity"


def test_policy_other_schema_name_is_could_not_look():
    doc = _doc(RPO)
    doc["manifest"]["schema_name"] = "com.example.something_else_v9"
    r = _one(_b(doc))
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["vendor_word"] == "not_an_alert"


def test_audit_log_is_not_an_alert():
    r = _one(AUDIT)
    _sealed(r, AUDIT)
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["vendor_word"] == "not_an_alert"


def test_a_list_gives_one_row_per_alert_and_one_digest():
    raw = b"[" + b",".join([CONV, SCAN, CLEAN, RPO, AUDIT]) + b"]"
    rows = _ing(raw)
    assert [r["relayed_verdict"] for r in rows] == [BROKEN, BROKEN, VERIFIED, BROKEN,
                                                    COULD_NOT_LOOK]
    assert [r["alert"]["index"] for r in rows] == [0, 1, 2, 3, 4]
    for r in rows:
        _sealed(r, raw)


def test_too_many_alerts_is_bounded():
    raw = _b([_doc(CONV)] * (H.MAX_ROWS + 5))
    rows = _ing(raw)
    assert len(rows) == H.MAX_ROWS + 1
    assert rows[-1]["could_not_look"]["reason_word"] == "bounded"


# --- claims cannot sign a row --------------------------------------------------

def test_payload_claiming_a_signature_changes_nothing():
    doc = _doc(CLEAN)
    doc.update({"signed_by_vendor": True, "standing": "vendor_signed",
                "signature": "x" * 200, "attestation": {"sig": "y"}})
    r = _one(_b(doc))
    _sealed(r, _b(doc))


def test_conviction_spoofing_vendor_word_stays_broken():
    doc = _doc(CONV)
    doc["verdict"] = "verified"
    assert _one(_b(doc))["relayed_verdict"] == BROKEN


# --- hostile input never raises ------------------------------------------------

@pytest.mark.parametrize("raw", ids=lambda b: f"{len(b)}b", argvalues=[
    b"", b"not json", b"\xff\xfe\x00", b"{\"a\":1,\"a\":2}", b"null", b"42", b"\"s\"",
    b"[]", b"{}", b"[1, \"x\", null]", b"{\"scan_result_summary\": 5}",
    b"{\"conviction_id\": [1]}", b"{\"manifest\": {}, \"evaluation\": 7}",
    b"{\"scan_result_summary\": {\"status\": \"done\", \"detection_count\": -1}}",
    b"[" * 5000 + b"]" * 5000,
    b"{\"x\": \"" + b"a" * (H.MAX_PAYLOAD_BYTES + 1) + b"\"}",
])
def test_hostile_bytes_never_raise_and_never_verify(raw):
    rows = _ing(raw)
    assert rows
    for r in rows:
        _sealed(r, raw)
        assert r["relayed_verdict"] != VERIFIED


@pytest.mark.parametrize("raw", [None, 12, {"a": 1}, ["x"], object()])
def test_non_bytes_never_raise(raw):
    rows = _ing(raw)
    assert len(rows) == 1 and rows[0]["relayed_verdict"] == COULD_NOT_LOOK
    _sealed(rows[0])
    assert rows[0]["input_sha256"] is None


def test_str_input_hashes_its_utf8_bytes():
    r = _one(CONV.decode())
    assert r["input_sha256"] == hashlib.sha256(CONV).hexdigest()


def test_recheck_says_could_not_look():
    r = _one(CONV)
    assert recheck(r, CONV)["verdict"] == COULD_NOT_LOOK


# --- standing verdict / rollup -------------------------------------------------

def test_standing_verdict_never_verified_even_all_clean():
    sv = H.standing_verdict(_ing(CLEAN))
    assert sv["verdict"] == COULD_NOT_LOOK and sv["relayed_verdict"] == COULD_NOT_LOOK
    assert sv["signed_by_vendor"] is False and sv["standing"] == "reported_by_sender"
    assert H.rollup is H.standing_verdict


def test_standing_verdict_broken_wins():
    rows = _ing(b"[" + b",".join([CLEAN, CONV]) + b"]")
    sv = H.standing_verdict(rows)
    assert sv["verdict"] == BROKEN and sv["relayed_verdict"] == BROKEN
    assert sv["counts"] == {VERIFIED: 1, BROKEN: 1, COULD_NOT_LOOK: 0}


@pytest.mark.parametrize("rows", [None, [], "x", [1, None], [{"relayed_verdict": "BROKEN"}]])
def test_standing_verdict_ignores_foreign_rows(rows):
    sv = H.standing_verdict(rows)
    assert sv["verdict"] == COULD_NOT_LOOK and sv["relayed_verdict"] == COULD_NOT_LOOK


def test_doc_section_exists_with_what_this_cannot_prove():
    text = (ROOT / "docs" / "CONNECTOR_ADAPTER.md").read_text(encoding="utf-8")
    i = text.index("## HiddenLayer alerts")
    sec = text[i:text.index("\n## ", i + 5)]
    assert "### What this cannot prove" in sec
    assert "docs.hiddenlayer.ai" in sec


def test_module_docstring_cites_public_docs():
    assert "https://docs.hiddenlayer.ai/docs/integrations/webhook_integrations.md" in H.__doc__
