# SPDX-License-Identifier: MIT
"""L2-02: Snyk agent-scan (formerly Invariant mcp-scan) `--json` output becomes
relayed check rows on connector.core, one per finding plus one per clean or
unreadable target. The fixtures are synthetic, shaped from the published JSON
notes, not a live capture. No network.

R15: no vendor signs its verdicts, so every row says `signed_by_vendor: false`
and is reported by sender; such rows alone never make a VERIFIED (T4), and a
relayed BROKEN never turns into VERIFIED (stack review F12)."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest

from arcaeon.connector import ROW_KIND, VendorAdapter, adapter_for, import_verdict, recheck
from arcaeon.connector import snyk_agent_scan as S
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "snyk_agent_scan"
CLEAN = (FIX / "v06_clean.json").read_bytes()
FINDINGS = (FIX / "v06_findings.json").read_bytes()
V05 = (FIX / "v05_findings.json").read_bytes()
AT = "2026-10-05T12:00:00Z"


def _rows(raw, **kw):
    return S.ingest(raw, received_at=AT, **kw)


def _summary(rows):
    return [(r["vendor_word"], r["relayed_verdict"]) for r in rows]


# ------------------------------------------------------------------ the base

def test_adapter_is_on_the_one_base_and_registered():
    assert isinstance(S.SNYK_AGENT_SCAN, VendorAdapter)
    assert S.SNYK_AGENT_SCAN.one_row_per_payload is False
    assert adapter_for("snyk-agent-scan") is S.SNYK_AGENT_SCAN
    assert S.SNYK_AGENT_SCAN.version == "1"


def test_table_maps_only_into_our_three_words_and_nothing_unknown_is_verified():
    assert set(S.TABLE.values()) <= {VERIFIED, BROKEN, COULD_NOT_LOOK}
    assert [w for w, v in S.TABLE.items() if v == VERIFIED] == ["no_findings"]


# ------------------------------------------------------------------ clean scan

def test_clean_scan_gives_one_row_per_server_and_skill():
    rows = _rows(CLEAN)
    assert _summary(rows) == [("no_findings", VERIFIED)] * 3
    names = [(r["finding"]["target_kind"], r["finding"]["target_name"]) for r in rows]
    assert names == [("server", "files"), ("server", "notes"), ("skill", "summarize")]
    for r in rows:
        assert r["kind"] == ROW_KIND and r["relayed"] is True and r["checked_by_us"] is False
        assert "verdict" not in r
        assert r["vendor"] == {"name": "snyk-agent-scan", "adapter_version": "1"}
        assert r["finding"]["format"] == "v0.6-scan-response"
        assert r["finding"]["client"] == "cursor"
        assert r["received_at"] == AT
        assert "could_not_look" not in r


# ------------------------------------------------------------------ severity mapping

def test_v06_scores_map_by_the_declared_threshold():
    rows = _rows(FINDINGS, broken_at_score=500)
    got = [(r["finding"]["target_name"], r["finding"]["risk"], r["finding"]["score"],
            r["vendor_word"], r["relayed_verdict"]) for r in rows]
    assert got == [
        ("weather", "prompt_injection_tool_desc", 870, "risk_at_or_over_threshold", BROKEN),
        ("weather", "untrusted_content", 120, "risk_below_threshold", COULD_NOT_LOOK),
        ("files", None, None, "no_findings", VERIFIED),
        ("broken-server", None, None, "error", COULD_NOT_LOOK),
        ("deploy", "malicious_code_patterns", 640, "risk_at_or_over_threshold", BROKEN),
        ("deploy", "hidden_unicode", None, "risk_unscored", COULD_NOT_LOOK),
        (None, None, None, "error", COULD_NOT_LOOK),
    ]
    assert rows[0]["finding"]["affected_tools"] == [2]
    assert rows[0]["finding"]["threshold"] == 500
    assert rows[0]["subject"]["name"] == "snyk-agent-scan:cursor/weather"


def test_v06_scores_without_a_threshold_never_map():
    rows = _rows(FINDINGS)
    scored = [r for r in rows if r["finding"]["score"] is not None]
    assert scored and all(r["vendor_word"] == "risk_no_threshold" for r in scored)
    assert all(r["relayed_verdict"] == COULD_NOT_LOOK for r in scored)
    assert all(r["could_not_look"]["reason_word"] == "name_not_found" for r in scored)


def test_the_threshold_boundary_is_inclusive():
    rows = _rows(FINDINGS, broken_at_score=870)
    assert rows[0]["relayed_verdict"] == BROKEN
    rows = _rows(FINDINGS, broken_at_score=871)
    assert rows[0]["relayed_verdict"] == COULD_NOT_LOOK


@pytest.mark.parametrize("bad", [-1, 1001, 1.5, True, "500"])
def test_a_bad_threshold_is_a_caller_error(bad):
    with pytest.raises(ValueError):
        S.ingest(FINDINGS, broken_at_score=bad)


def test_v05_issue_codes_map_by_their_letter():
    rows = _rows(V05)
    got = [(r["finding"]["target_name"], r["finding"]["code"], r["finding"]["severity"],
            r["vendor_word"], r["relayed_verdict"]) for r in rows]
    assert got == [
        ("weather", "E001", "error", "issue_error", BROKEN),
        ("weather", "W008", "warning", "issue_warning", BROKEN),
        ("weather", "Q999", None, "unknown_code", COULD_NOT_LOOK),
        ("files", None, None, "no_findings", VERIFIED),
        ("mail", None, None, "error", COULD_NOT_LOOK),
        ("mail", "X002", "failure", "scan_failure", COULD_NOT_LOOK),
    ]
    assert rows[0]["finding"]["reference"] == [0, 0]
    assert all(r["finding"]["format"] == "v0.5-path-keyed" for r in rows)


def test_v05_without_issues_is_not_analyzed_not_clean():
    doc = json.loads(V05)
    del doc["~/.cursor/mcp.json"]["issues"]
    rows = _rows(json.dumps(doc).encode())
    assert {r["vendor_word"] for r in rows} <= {"not_analyzed", "error"}
    assert all(r["relayed_verdict"] == COULD_NOT_LOOK for r in rows)


def test_a_path_wide_issue_blocks_every_clean_row_on_the_path():
    doc = json.loads(V05)
    doc["~/.cursor/mcp.json"]["issues"] = [{"code": "E002", "message": "m", "reference": None}]
    rows = _rows(json.dumps(doc).encode())
    assert ("no_findings", VERIFIED) not in _summary(rows)
    assert ("issue_error", BROKEN) in _summary(rows)


def test_evidence_is_kept_by_digest_only():
    rows = _rows(FINDINGS, broken_at_score=500)
    blob = json.dumps(rows)
    assert "synthetic evidence text" not in blob
    assert rows[0]["finding"]["evidence_digest"] == S.SNYK_AGENT_SCAN.digest(
        "synthetic evidence text")


# ------------------------------------------------------------------ R15: unsigned, always

def test_every_row_says_signed_by_vendor_false_and_reported_by_sender():
    for raw in (CLEAN, FINDINGS, V05, b"", b"not json", b"[]"):
        for r in _rows(raw, broken_at_score=500):
            assert r["signed_by_vendor"] is False
            assert r["standing"] == "reported_by_sender"
            assert r["attestation"]["status"] == "NONE"
            assert r["attestation"]["claimed"] is None


def test_a_signature_looking_field_still_yields_false():
    doc = json.loads(CLEAN)
    doc["signature"] = {"alg": "ed25519", "kid": "snyk-1", "sig": "A" * 128}
    doc["signed"] = True
    doc["signed_by_vendor"] = True
    doc["attestation"] = {"status": "VERIFIED"}
    doc["scan_path_responses"][0]["server_risks"][0]["signature"] = "B" * 88
    rows = _rows(json.dumps(doc).encode())
    assert rows and all(r["signed_by_vendor"] is False for r in rows)
    assert all(r["attestation"]["status"] == "NONE" for r in rows)
    v05 = _rows(V05)
    assert all(r["signed_by_vendor"] is False for r in v05)  # v0.5 `signature` = tool catalog


def test_no_parameter_can_set_signed_by_vendor():
    params = inspect.signature(S.ingest).parameters
    assert not [p for p in params if "sign" in p.lower() or "attest" in p.lower()]
    with pytest.raises(TypeError):
        S.ingest(CLEAN, signed_by_vendor=True)


# ------------------------------------------------------------------ T4 / F12

def test_unsigned_rows_alone_never_make_verified():
    rows = _rows(CLEAN)
    assert all(r["relayed_verdict"] == VERIFIED for r in rows)
    got = S.standing_verdict(rows)
    assert got["relayed_verdict"] == COULD_NOT_LOOK
    assert "verdict" not in got and got["signed_by_vendor"] is False
    assert got["counts"][VERIFIED] == len(rows) and got["rows"] == len(rows)


def test_a_relayed_broken_is_broken_never_verified():
    rows = _rows(FINDINGS, broken_at_score=500)
    got = S.standing_verdict(rows)
    assert got["relayed_verdict"] == BROKEN and "verdict" not in got
    one_broken = [r for r in rows if r["relayed_verdict"] == BROKEN][:1]
    assert S.standing_verdict(one_broken + _rows(CLEAN))["relayed_verdict"] == BROKEN


def test_a_relayed_broken_row_edited_to_say_signed_is_still_broken():
    row = [r for r in _rows(V05) if r["relayed_verdict"] == BROKEN][0]
    row["signed_by_vendor"] = True
    row["attestation"] = {"status": "VERIFIED", "checked_by_us": True, "claimed": {}}
    assert S.standing_verdict([row])["relayed_verdict"] == BROKEN


def test_standing_verdict_on_nothing_is_could_not_look():
    for rows in ([], None, "rows", [{"kind": "x"}]):
        assert S.standing_verdict(rows)["relayed_verdict"] == COULD_NOT_LOOK


# ------------------------------------------------------------------ digests and ids

def test_input_sha256_is_over_the_exact_bytes_read():
    for raw in (CLEAN, FINDINGS, V05, b"not json", CLEAN + b"\n"):
        want = hashlib.sha256(raw).hexdigest()
        for r in _rows(raw):
            assert r["input_sha256"] == want
            assert r["vendor_payload_digest"].endswith(want)
            assert r["vendor_payload_bytes"] == len(raw)
    assert _rows(CLEAN)[0]["input_sha256"] != _rows(CLEAN + b" ")[0]["input_sha256"]


def test_str_input_is_hashed_as_its_utf8_bytes():
    assert _rows(CLEAN.decode("utf-8"))[0]["input_sha256"] == hashlib.sha256(CLEAN).hexdigest()


def test_vendor_request_id_when_given_else_null():
    assert all(r["vendor_request_id"] is None and r["vendor_id"] is None for r in _rows(CLEAN))
    rows = _rows(CLEAN, vendor_request_id="req-synthetic-0001")
    assert all(r["vendor_request_id"] == "req-synthetic-0001" for r in rows)
    assert all(r["vendor_id"] == "req-synthetic-0001" for r in rows)
    assert _rows(CLEAN, vendor_request_id=42)[0]["vendor_request_id"] is None


def test_a_request_id_inside_the_payload_is_not_read():
    doc = json.loads(CLEAN)
    doc["request_id"] = "req-in-payload"
    doc["scan_id"] = "scan-in-payload"
    assert all(r["vendor_request_id"] is None for r in _rows(json.dumps(doc).encode()))


# ------------------------------------------------------------------ hostile input

@pytest.mark.parametrize("raw,why", [
    (b"", "empty"),
    (b"not json", "unreadable"),
    (b"{\"scan_path_responses\": [", "unreadable"),
    (b"\xff\xfe\x00garbage", "unreadable"),
    (b"{\"a\": 1, \"a\": 2}", "unreadable"),
    (b"[]", "name_not_found"),
    (b"{\"anything\": true}", "name_not_found"),
    (b"{\"scan_path_responses\": []}", "empty"),
    (b"[" * 200 + b"]" * 200, "unreadable"),
])
def test_malformed_input_is_one_could_not_look_row_never_a_crash(raw, why):
    rows = _rows(raw)
    assert len(rows) == 1
    assert rows[0]["relayed_verdict"] == COULD_NOT_LOOK
    assert rows[0]["could_not_look"]["reason_word"] == why
    assert rows[0]["signed_by_vendor"] is False


def test_never_raises_on_non_bytes():
    rows = _rows(None)
    assert len(rows) == 1 and rows[0]["relayed_verdict"] == COULD_NOT_LOOK
    assert rows[0]["input_sha256"] is None and rows[0]["signed_by_vendor"] is False


def test_oversized_input_is_bounded_and_still_digested():
    big = b" " * (S.MAX_PAYLOAD_BYTES + 1)
    rows = _rows(big)
    assert len(rows) == 1 and rows[0]["could_not_look"]["reason_word"] == "bounded"
    assert rows[0]["input_sha256"] == hashlib.sha256(big).hexdigest()


def test_too_many_findings_are_bounded(monkeypatch):
    monkeypatch.setattr(S, "MAX_ROWS", 2)
    rows = _rows(FINDINGS, broken_at_score=500)
    assert len(rows) == 3 and rows[-1]["could_not_look"]["reason_word"] == "bounded"


def test_garbage_entries_are_their_own_rows():
    doc = {"scan_path_responses": [7, {"client": "c", "path": "p", "error": None,
                                       "server_risks": ["x", {"name": "s", "risk_indexes": {
                                           "r": 5}, "error": None}]}]}
    rows = _rows(json.dumps(doc).encode(), broken_at_score=1)
    assert [r["relayed_verdict"] for r in rows] == [COULD_NOT_LOOK] * 3
    assert rows[2]["vendor_word"] == "risk_unscored"


def test_long_strings_are_cut():
    doc = json.loads(CLEAN)
    doc["scan_path_responses"][0]["server_risks"][0]["name"] = "n" * 5000
    r = _rows(json.dumps(doc).encode())[0]
    assert len(r["finding"]["target_name"]) == 256


def test_not_rechecked_or_imported_as_one_verdict():
    rows = _rows(CLEAN)
    assert recheck(rows[0], CLEAN)["verdict"] == COULD_NOT_LOOK
    assert import_verdict(S.SNYK_AGENT_SCAN, CLEAN)["relayed_verdict"] == COULD_NOT_LOOK


def test_the_doc_states_the_mapping_table_and_its_limits():
    doc = (ROOT / "docs" / "CONNECTOR_ADAPTER.md").read_text(encoding="utf-8")
    body = doc[doc.index("## Snyk agent-scan"):]
    body = body[:body.index("\n## ", 5)]
    for word, ours in S.TABLE.items():
        assert f"| `{word}` | {ours} |" in body, word
    assert "### What this cannot prove" in body
    assert "signed_by_vendor: false" in body
    for phrase in ("tamper-proof", "guarantee", "—", "–"):
        assert phrase not in body.lower(), phrase
