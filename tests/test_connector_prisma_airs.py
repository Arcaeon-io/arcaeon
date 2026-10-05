# SPDX-License-Identifier: MIT
"""L2-04: Palo Alto Prisma AIRS (AI Runtime Security) scan results become relayed
check rows on connector.core, one per scan or detection result. The fixtures are
synthetic, shaped from the published API notes (R15), not a live capture. No
network.

R15: Prisma does not sign its verdicts, so every row says `signed_by_vendor:
false` and is reported by sender; such rows alone never make a VERIFIED (T4), and
a relayed BROKEN never turns into VERIFIED (stack review F12). Prisma is the one
vendor of the three with a re-fetch by id; the helper only DESCRIBES that
request, and a re-fetch is a second report from the same vendor, not a signature."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest

from arcaeon.connector import ROW_KIND, VendorAdapter, adapter_for, import_verdict, recheck
from arcaeon.connector import prisma_airs as P
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "prisma_airs"
BLOCK = (FIX / "sync_block.json").read_bytes()
ALLOW = (FIX / "sync_allow.json").read_bytes()
ALLOW_DET = (FIX / "sync_allow_detected.json").read_bytes()
ACK = (FIX / "async_ack.json").read_bytes()
RESULTS = (FIX / "scan_results.json").read_bytes()
REPORT = (FIX / "report.json").read_bytes()
ALL = (BLOCK, ALLOW, ALLOW_DET, ACK, RESULTS, REPORT)
AT = "2026-10-05T12:00:00Z"
SCAN1 = "00000000-0000-4000-8000-000000000001"
REP1 = "R00000000-0000-4000-8000-000000000001"


def _rows(raw, **kw):
    return P.ingest(raw, received_at=AT, **kw)


def _summary(rows):
    return [(r["vendor_word"], r["relayed_verdict"]) for r in rows]


# ------------------------------------------------------------------ the base

def test_adapter_is_on_the_one_base_and_registered():
    assert isinstance(P.PRISMA_AIRS, VendorAdapter)
    assert P.PRISMA_AIRS.one_row_per_payload is False
    assert adapter_for("prisma-airs") is P.PRISMA_AIRS
    assert P.PRISMA_AIRS.version == "3"


def test_table_maps_only_into_our_three_words_and_nothing_unknown_is_verified():
    assert set(P.TABLE.values()) <= {VERIFIED, BROKEN, COULD_NOT_LOOK}
    assert [w for w, v in P.TABLE.items() if v == VERIFIED] == ["allow"]
    assert [w for w, v in P.TABLE.items() if v == BROKEN] == ["block"]


# ------------------------------------------------------------------ the mapping

def test_sync_block_is_broken():
    rows = _rows(BLOCK)
    assert _summary(rows) == [("block", BROKEN)]
    r = rows[0]
    assert r["kind"] == ROW_KIND and r["relayed"] is True and r["checked_by_us"] is False
    assert "verdict" not in r
    assert r["vendor"] == {"name": "prisma-airs", "adapter_version": "3"}
    f = r["finding"]
    assert f["format"] == "sync-scan-response"
    assert f["action"] == "block" and f["category"] == "malicious"
    assert f["prompt_detected"] == ["injection"] and f["response_detected"] == []
    assert f["profile_name"] == "synthetic-profile"
    assert r["subject"] == {"name": f"prisma-airs:scan/{SCAN1}", "sha256": None}
    assert r["received_at"] == AT and "could_not_look" not in r


def test_sync_allow_with_no_detection_is_verified_as_relayed():
    rows = _rows(ALLOW)
    assert _summary(rows) == [("allow", VERIFIED)]
    assert rows[0]["finding"]["prompt_detected"] == []


def test_allow_with_a_detection_flag_true_is_not_a_pass():
    rows = _rows(ALLOW_DET)
    assert _summary(rows) == [("allow_with_detection", COULD_NOT_LOOK)]
    assert rows[0]["finding"]["prompt_detected"] == ["url_cats"]
    assert rows[0]["could_not_look"]["reason_word"] == "name_not_found"


def test_allow_with_a_malicious_category_is_not_a_pass():
    doc = json.loads(ALLOW)
    doc["category"] = "malicious"
    assert _summary(_rows(json.dumps(doc).encode())) == [("allow_with_detection",
                                                           COULD_NOT_LOOK)]


@pytest.mark.parametrize("flags", ["yes", {"dlp": "true"}, {"dlp": 1}, ["dlp"]])
def test_an_unreadable_detection_flag_on_allow_is_could_not_look(flags):
    doc = json.loads(ALLOW)
    doc["response_detected"] = flags
    assert _summary(_rows(json.dumps(doc).encode())) == [("detection_unreadable",
                                                           COULD_NOT_LOOK)]


def test_block_stays_block_whatever_the_flags_say():
    doc = json.loads(BLOCK)
    doc["prompt_detected"] = "garbage"
    doc["category"] = "benign"
    assert _summary(_rows(json.dumps(doc).encode())) == [("block", BROKEN)]


@pytest.mark.parametrize("action", [None, 1, True, "alert", "", "allowed", "ALLOW "])
def test_unknown_actions_never_map_to_a_pass(action):
    doc = json.loads(ALLOW)
    doc["action"] = action
    rows = _rows(json.dumps(doc).encode())
    if action == "ALLOW ":  # strip + casefold, as the base does for every word
        assert _summary(rows) == [("allow", VERIFIED)]
        assert rows[0]["finding"]["action"] == "ALLOW "
    else:
        assert _summary(rows) == [("unknown_action", COULD_NOT_LOOK)]


def test_async_ack_carries_ids_but_no_verdict():
    rows = _rows(ACK)
    assert _summary(rows) == [("pending", COULD_NOT_LOOK)]
    r = rows[0]
    assert r["finding"]["format"] == "async-scan-ack"
    assert r["vendor_request_id"] == "00000000-0000-4000-8000-000000000004"
    assert r["ids"]["report_id"] == "R00000000-0000-4000-8000-000000000004"
    assert r["could_not_look"]["reason_word"] == "missing"


def test_scan_results_give_one_row_per_item():
    rows = _rows(RESULTS)
    assert _summary(rows) == [("block", BROKEN), ("allow", VERIFIED),
                              ("pending", COULD_NOT_LOOK)]
    assert [r["finding"]["status"] for r in rows] == ["complete", "complete", "pending"]
    assert [r["ids"]["req_id"] for r in rows] == [1, 2, 3]
    assert rows[0]["finding"]["prompt_detected"] == ["dlp"]
    assert rows[0]["ids"]["tr_id"] == "tr-synthetic-0005"
    assert all(r["finding"]["format"] == "scan-results" for r in rows)


def _results_with_status(status, drop=False):
    """The fixture's allow item (req_id 2) with its `status` changed (or dropped).
    The success value is "complete": the one status tests/fixtures/prisma_airs/
    scan_results.json gives an item that carries a result (R15 marks the full
    set of status values unverified, so nothing else is read as success)."""
    items = json.loads(RESULTS)
    it = items[1]
    assert it["status"] == "complete" and it["result"]["action"] == "allow"
    if drop:
        del it["status"]
    else:
        it["status"] = status
    return json.dumps([it]).encode()


@pytest.mark.parametrize("status", ["failed", "pending", "error", "", "COMPLETED", 7, None])
def test_scan_results_allow_with_a_non_success_status_is_not_verified(status):
    """Review F-R7: status "failed" + action allow read VERIFIED; `status` was
    recorded in `finding` but never read."""
    row, = _rows(_results_with_status(status))
    assert row["relayed_verdict"] == COULD_NOT_LOOK
    assert row["vendor_word"] == "status_not_complete"
    assert row["could_not_look"]["reason_word"] == "name_not_found"
    assert f"status {json.dumps(status)}" in row["could_not_look"]["reason"]


def test_scan_results_allow_with_no_status_is_not_verified():
    row, = _rows(_results_with_status(None, drop=True))
    assert row["relayed_verdict"] == COULD_NOT_LOOK
    assert row["vendor_word"] == "status_not_complete"
    assert "no status" in row["could_not_look"]["reason"]


def test_scan_results_complete_still_reads_and_block_stays_broken():
    assert _rows(_results_with_status(" Complete "))[0]["relayed_verdict"] == VERIFIED
    items = json.loads(RESULTS)
    items[0]["status"] = "failed"  # a block is BROKEN whatever else the item says
    assert _rows(json.dumps(items[:1]).encode())[0]["relayed_verdict"] == BROKEN


def test_report_gives_one_row_per_detection_result():
    rows = _rows(REPORT)
    assert _summary(rows) == [("allow", VERIFIED), ("block", BROKEN),
                              ("allow_with_detection", COULD_NOT_LOOK)]
    f = rows[1]["finding"]
    assert f["format"] == "threat-scan-report"
    assert (f["data_type"], f["detection_service"], f["report_verdict"]) == (
        "prompt", "pi", "malicious")
    assert all(r["vendor_request_id"] == "00000000-0000-4000-8000-000000000008" for r in rows)


def test_result_detail_is_kept_by_digest_only():
    rows = _rows(REPORT)
    assert "synthetic detail text" not in json.dumps(rows)
    assert rows[0]["finding"]["detail_digest"] == P.PRISMA_AIRS.digest(
        {"note": "synthetic detail text"})


# ------------------------------------------------------------------ R15: unsigned, always

def test_every_row_says_signed_by_vendor_false_and_reported_by_sender():
    for raw in ALL + (b"", b"not json", b"[]", b"{}", None):
        for r in _rows(raw):
            assert r["signed_by_vendor"] is False
            assert r["standing"] == "reported_by_sender"
            assert r["attestation"] == {"status": "NONE", "checked_by_us": False,
                                        "claimed": None}


def test_a_signature_looking_field_still_yields_false():
    for raw in (BLOCK, ALLOW):
        doc = json.loads(raw)
        doc["signature"] = {"alg": "ed25519", "kid": "pan-1", "sig": "A" * 128}
        doc["signed"] = True
        doc["signed_by_vendor"] = True
        doc["standing"] = "verified_by_vendor"
        doc["attestation"] = {"status": "VERIFIED", "checked_by_us": True}
        doc["x-pan-signature"] = "B" * 88
        rows = _rows(json.dumps(doc).encode())
        assert len(rows) == 1
        r = rows[0]
        assert r["signed_by_vendor"] is False and r["standing"] == "reported_by_sender"
        assert r["attestation"]["status"] == "NONE"
    res = json.loads(RESULTS)
    res[1]["result"]["signature"] = "C" * 88
    res[1]["signed_by_vendor"] = True
    assert all(r["signed_by_vendor"] is False for r in _rows(json.dumps(res).encode()))


def test_no_parameter_can_set_signed_by_vendor_or_standing():
    params = inspect.signature(P.ingest).parameters
    bad = [p for p in params if any(w in p.lower() for w in ("sign", "attest", "stand",
                                                             "trust", "verif"))]
    assert not bad
    for kw in ("signed_by_vendor", "standing", "attestation"):
        with pytest.raises(TypeError):
            P.ingest(ALLOW, **{kw: True})


def test_the_seal_is_the_last_step():
    row = {"signed_by_vendor": True, "standing": "x", "attestation": {"status": "CLAIMED"}}
    P._seal(row)
    assert row["signed_by_vendor"] is False and row["standing"] == "reported_by_sender"
    assert row["attestation"]["status"] == "NONE"


# ------------------------------------------------------------------ T4 / F12

def test_unsigned_rows_alone_never_make_verified():
    rows = _rows(ALLOW)
    assert rows[0]["relayed_verdict"] == VERIFIED
    got = P.standing_verdict(rows)
    assert got["relayed_verdict"] == COULD_NOT_LOOK
    assert "verdict" not in got and got["signed_by_vendor"] is False
    assert got["counts"][VERIFIED] == len(rows) and got["rows"] == len(rows)
    assert got["standing"] == "reported_by_sender"


def test_a_relayed_broken_is_broken_never_verified():
    assert P.standing_verdict(_rows(BLOCK))["relayed_verdict"] == BROKEN
    mixed = _rows(ALLOW) + _rows(BLOCK) + _rows(ALLOW)
    got = P.standing_verdict(mixed)
    assert got["relayed_verdict"] == BROKEN and "verdict" not in got
    assert P.standing_verdict(_rows(RESULTS))["relayed_verdict"] == BROKEN


def test_a_relayed_broken_row_edited_to_say_signed_is_still_broken():
    row = _rows(BLOCK)[0]
    row["signed_by_vendor"] = True
    row["standing"] = "verified_by_vendor"
    row["attestation"] = {"status": "VERIFIED", "checked_by_us": True, "claimed": {}}
    assert P.standing_verdict([row])["relayed_verdict"] == BROKEN


def test_an_allow_row_edited_to_say_signed_is_still_not_verified():
    row = _rows(ALLOW)[0]
    row["signed_by_vendor"] = True
    assert P.standing_verdict([row])["relayed_verdict"] == COULD_NOT_LOOK


def test_standing_verdict_on_nothing_is_could_not_look():
    for rows in ([], None, "rows", [{"kind": "x"}], _rows(BLOCK) and [{"vendor": 1}]):
        assert P.standing_verdict(rows)["relayed_verdict"] == COULD_NOT_LOOK


def test_other_vendors_rows_do_not_count():
    other = dict(_rows(BLOCK)[0], vendor={"name": "someone-else", "adapter_version": "1"})
    assert P.standing_verdict([other])["relayed_verdict"] == COULD_NOT_LOOK


# ------------------------------------------------------------------ digests and ids

def test_input_sha256_is_over_the_exact_bytes_read():
    for raw in ALL + (b"not json", BLOCK + b"\n"):
        want = hashlib.sha256(raw).hexdigest()
        for r in _rows(raw):
            assert r["input_sha256"] == want
            assert r["vendor_payload_digest"].endswith(want)
            assert r["vendor_payload_bytes"] == len(raw)
    assert _rows(BLOCK)[0]["input_sha256"] != _rows(BLOCK + b" ")[0]["input_sha256"]


def test_str_input_is_hashed_as_its_utf8_bytes():
    assert _rows(BLOCK.decode("utf-8"))[0]["input_sha256"] == hashlib.sha256(BLOCK).hexdigest()


def test_vendor_request_id_is_the_scan_id_with_the_other_ids_kept():
    r = _rows(BLOCK)[0]
    assert r["vendor_request_id"] == SCAN1 and r["vendor_id"] == SCAN1
    assert r["ids"] == {"scan_id": SCAN1, "report_id": REP1, "tr_id": "tr-synthetic-0001",
                        "req_id": None}


def test_vendor_request_id_falls_back_to_the_report_id():
    doc = json.loads(BLOCK)
    del doc["scan_id"]
    r = _rows(json.dumps(doc).encode())[0]
    assert r["vendor_request_id"] == REP1 and r["ids"]["scan_id"] is None


def test_no_id_is_null():
    doc = json.loads(BLOCK)
    del doc["scan_id"], doc["report_id"]
    r = _rows(json.dumps(doc).encode())[0]
    assert r["vendor_request_id"] is None and r["refetch"] is None
    doc["scan_id"] = 42
    assert _rows(json.dumps(doc).encode())[0]["vendor_request_id"] is None


def test_each_row_carries_its_refetch_description():
    r = _rows(BLOCK)[0]
    assert r["refetch"] == P.refetch_request(SCAN1)
    doc = json.loads(BLOCK)
    doc["scan_id"] = "../../admin?x=1"
    r = _rows(json.dumps(doc).encode())[0]
    assert r["vendor_request_id"] == "../../admin?x=1"  # recorded as sent ...
    assert r["refetch"] == P.refetch_request(REP1)       # ... never put in a path


# ------------------------------------------------------------------ the re-fetch helper

def test_refetch_by_scan_id_is_a_description_only():
    d = P.refetch_request(SCAN1)
    assert d["method"] == "GET" and d["path"] == "/v1/scan/results"
    assert d["query"] == {"scan_ids": SCAN1} and d["id"] == SCAN1
    assert d["id_kind"] == "scan_id"
    assert d["network"] is False and d["credentials"] is None
    assert "not a signature" in d["note"]
    assert "host" not in d and "headers" not in d


def test_refetch_by_report_id():
    d = P.refetch_request(REP1)
    assert (d["method"], d["path"], d["query"], d["id_kind"]) == (
        "GET", "/v1/scan/reports", {"report_ids": REP1}, "report_id")


@pytest.mark.parametrize("bad", [None, 7, b"x", "", "0000", "R", "../etc",
                                 SCAN1 + "?x=1", " " + SCAN1, SCAN1.upper() + "Z",
                                 "R" + REP1, "r" + SCAN1, SCAN1 + "\n",
                                 "00000000-0000-4000-8000-00000000000g"])
def test_refetch_rejects_ids_not_of_the_documented_shape(bad):
    with pytest.raises(ValueError):
        P.refetch_request(bad)


def test_refetch_makes_no_network_call(monkeypatch):
    import socket

    def boom(*a, **k):
        raise AssertionError("network")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    assert P.refetch_request(SCAN1)["network"] is False
    assert _rows(RESULTS)


def test_the_module_imports_no_network_library():
    src = Path(P.__file__).read_text(encoding="utf-8")
    for lib in ("urllib", "http.client", "socket", "requests", "httpx", "aiohttp"):
        assert f"import {lib}" not in src and f"from {lib}" not in src, lib


# ------------------------------------------------------------------ hostile input

@pytest.mark.parametrize("raw,why", [
    (b"", "empty"),
    (b"not json", "unreadable"),
    (b"{\"action\": \"allow\"", "unreadable"),
    (b"\xff\xfe\x00garbage", "unreadable"),
    (b"{\"action\": \"allow\", \"action\": \"block\"}", "unreadable"),
    (b"{\"scan_id\": \"a\", \"scan_id\": \"b\", \"action\": \"allow\"}", "unreadable"),
    (b"[]", "empty"),
    (b"{}", "name_not_found"),
    (b"7", "name_not_found"),
    (b"{\"anything\": true}", "name_not_found"),
    (b"[" * 200 + b"]" * 200, "unreadable"),
    (b"{\"action\": " + b"[" * 100 + b"]" * 100 + b"}", "unreadable"),
])
def test_malformed_input_is_one_could_not_look_row_never_a_crash(raw, why):
    rows = _rows(raw)
    assert len(rows) == 1
    assert rows[0]["relayed_verdict"] == COULD_NOT_LOOK
    assert rows[0]["could_not_look"]["reason_word"] == why
    assert rows[0]["signed_by_vendor"] is False
    assert rows[0]["input_sha256"] == hashlib.sha256(raw).hexdigest()


def test_never_raises_on_non_bytes():
    for raw in (None, 7, ["x"]):
        rows = _rows(raw)
        assert len(rows) == 1 and rows[0]["relayed_verdict"] == COULD_NOT_LOOK
        assert rows[0]["input_sha256"] is None and rows[0]["signed_by_vendor"] is False


def test_oversized_input_is_bounded_and_still_digested():
    assert P.MAX_PAYLOAD_BYTES == 8 << 20
    big = b" " * (P.MAX_PAYLOAD_BYTES + 1)
    rows = _rows(big)
    assert len(rows) == 1 and rows[0]["could_not_look"]["reason_word"] == "bounded"
    assert rows[0]["input_sha256"] == hashlib.sha256(big).hexdigest()
    assert rows[0]["vendor_payload_bytes"] == len(big)


def test_too_many_rows_are_bounded(monkeypatch):
    monkeypatch.setattr(P, "MAX_ROWS", 2)
    rows = _rows(REPORT)
    assert len(rows) == 3 and rows[-1]["could_not_look"]["reason_word"] == "bounded"


def test_garbage_entries_are_their_own_rows():
    doc = [7, {"scan_id": SCAN1, "status": "complete", "result": "nope"},
           {"report_id": REP1, "detection_results": ["x"]}, {"what": 1}]
    rows = _rows(json.dumps(doc).encode())
    assert [r["relayed_verdict"] for r in rows] == [COULD_NOT_LOOK] * 4
    assert rows[1]["vendor_word"] == "pending" and rows[1]["vendor_request_id"] == SCAN1


def test_long_strings_are_cut():
    doc = json.loads(BLOCK)
    doc["profile_name"] = "n" * 5000
    doc["prompt_detected"] = {("k" * 400): True}
    r = _rows(json.dumps(doc).encode())[0]
    assert len(r["finding"]["profile_name"]) == 256
    assert len(r["finding"]["prompt_detected"][0]) == 256


def test_not_rechecked_or_imported_as_one_verdict():
    rows = _rows(BLOCK)
    assert recheck(rows[0], BLOCK)["verdict"] == COULD_NOT_LOOK
    assert import_verdict(P.PRISMA_AIRS, BLOCK)["relayed_verdict"] == COULD_NOT_LOOK


# ------------------------------------------------------------------ the doc

def _section():
    doc = (ROOT / "docs" / "CONNECTOR_ADAPTER.md").read_text(encoding="utf-8")
    body = doc[doc.index("## Prisma AIRS"):]
    return body[:body.index("\n## ", 5)]


def test_the_doc_states_the_mapping_table_and_its_limits():
    body = _section()
    for word, ours in P.TABLE.items():
        assert f"| `{word}` | {ours} |" in body, word
    assert "### What this cannot prove" in body
    assert "signed_by_vendor: false" in body
    assert "second report from the same vendor, not a signature" in body
    for phrase in ("tamper-proof", "guarantee", "—", "–"):
        assert phrase not in body.lower(), phrase


def test_the_prisma_section_comes_after_the_other_adapter_sections():
    doc = (ROOT / "docs" / "CONNECTOR_ADAPTER.md").read_text(encoding="utf-8")
    p = doc.index("## Prisma AIRS")
    assert doc.index("## OPA decision logs") < p and doc.index("## Snyk agent-scan") < p
    assert p < doc.index("## The sha256:jcs:v1 digest")
