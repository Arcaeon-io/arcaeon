# SPDX-License-Identifier: MIT
"""L2-09: the SentinelOne alert export adapter. One relayed row per alert, always
unsigned, always reported_by_sender, never VERIFIED. Fixtures are shaped from
SentinelOne's public purple-mcp client, not a live capture. No network."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from arcaeon.connector import ROW_KIND, VendorAdapter, adapter_for, recheck
from arcaeon.connector import sentinelone as S
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "sentinelone"
LIST = (FIX / "alerts_list.json").read_bytes()
GET = (FIX / "alert_get.json").read_bytes()
SIGNED = (FIX / "claims_signed.json").read_bytes()
AT = "2026-10-05T12:00:00Z"


def _ing(raw, **kw):
    return S.ingest(raw, received_at=AT, **kw)


def _node(**fields):
    doc = {"id": "a-1", "status": "RESOLVED"}
    doc.update(fields)
    rows = _ing(json.dumps(doc).encode())
    assert len(rows) == 1
    return rows[0]


def _sealed(r):
    assert r["signed_by_vendor"] is False
    assert r["standing"] == "reported_by_sender"
    assert r["attestation"] == {"status": "NONE", "checked_by_us": False, "claimed": None}
    assert r["vendor"] == {"name": "sentinelone", "adapter_version": "1"}
    assert r["kind"] == ROW_KIND and r["relayed"] is True and r["checked_by_us"] is False
    assert r["relayed_verdict"] in (BROKEN, COULD_NOT_LOOK)
    assert "verdict" not in r


def test_adapter_is_on_the_one_base_and_registered():
    assert isinstance(S.SENTINELONE, VendorAdapter)
    assert S.SENTINELONE.one_row_per_payload is False
    assert adapter_for("sentinelone") is S.SENTINELONE
    assert VERIFIED not in S.TABLE.values()


def test_module_cites_its_public_source():
    assert "github.com/Sentinel-One/purple-mcp" in S.__doc__
    readme = (FIX / "README.md").read_text(encoding="utf-8")
    assert "github.com/Sentinel-One/purple-mcp" in readme
    assert "not a live capture" in readme


def test_list_response_one_row_per_alert():
    rows = _ing(LIST)
    assert [r["vendor_id"] for r in rows] == [f"synthetic-alert-000{i}" for i in range(1, 6)]
    assert [r["relayed_verdict"] for r in rows] == [BROKEN] + [COULD_NOT_LOOK] * 4
    assert [r["vendor_word"] for r in rows] == [
        "true_positive", "false_positive", "no_verdict", "no_verdict",
        "verdict_status_conflict"]
    sha = hashlib.sha256(LIST).hexdigest()
    for r in rows:
        _sealed(r)
        assert r["input_sha256"] == sha
        assert r["detection"]["format"] == "uam-graphql-alerts"
    d = rows[0]["detection"]
    assert d["analyst_verdict"] == "TRUE_POSITIVE_MALWARE" and d["status"] == "RESOLVED"
    assert d["severity"] == "HIGH" and d["asset_id"] == "synthetic-asset-01"
    assert rows[0]["subject"] == {"name": "sentinelone:alert/synthetic-alert-0001",
                                  "sha256": None}
    assert rows[0]["at"] == "2026-10-05T10:00:00Z"
    # host names and descriptions are not copied
    assert "synthetic-host-01" not in json.dumps(rows)
    assert "synthetic description" not in json.dumps(rows)
    for r in rows[1:]:
        assert "could_not_look" in r


def test_get_response_true_positive_is_broken():
    rows = _ing(GET)
    assert len(rows) == 1 and rows[0]["relayed_verdict"] == BROKEN
    assert rows[0]["detection"]["format"] == "uam-graphql-alert"
    _sealed(rows[0])


@pytest.mark.parametrize("v", sorted(S.TRUE_POSITIVE))
def test_every_true_positive_is_broken(v):
    assert _node(analystVerdict=v)["relayed_verdict"] == BROKEN


@pytest.mark.parametrize("v", sorted(S.FALSE_POSITIVE))
def test_every_false_positive_is_could_not_look(v):
    r = _node(analystVerdict=v)
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["vendor_word"] == "false_positive"


def test_status_false_positive_alone_is_could_not_look():
    r = _node(status="FALSE_POSITIVE", analystVerdict=None)
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["vendor_word"] == "false_positive"


@pytest.mark.parametrize("fields,word", [
    ({"analystVerdict": "TRUE_POSITIVE_SOMETHING_NEW"}, "unknown_verdict"),
    ({"analystVerdict": 7}, "unknown_verdict"),
    ({"analystVerdict": None, "status": "CLOSED"}, "unknown_status"),
    ({"analystVerdict": None, "status": 3}, "unknown_status"),
    ({"analystVerdict": "UNDEFINED", "status": "NEW"}, "no_verdict"),
])
def test_unknown_or_missing_is_could_not_look(fields, word):
    r = _node(**fields)
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["vendor_word"] == word
    _sealed(r)


def test_claims_of_a_signature_change_nothing():
    rows = _ing(SIGNED)
    assert len(rows) == 1
    _sealed(rows[0])
    assert "signature" in rows[0]["detection"]["ignored_keys"]


def test_vendor_request_id_is_the_callers():
    r = _ing(GET, vendor_request_id="req-9")[0]
    assert r["vendor_request_id"] == "req-9"
    assert _ing(GET)[0]["vendor_request_id"] is None


@pytest.mark.parametrize("raw", [
    b"", b"not json", b"\xff\xfe", b"[1, 2]", b"42", b'"text"', b"{}", b"null",
    b'{"a": 1, "a": 2}', b"[" * 5000 + b"]" * 5000, b'{"data": null, "errors": [{}]}',
    b'{"data": {"alerts": {"edges": "no"}}}', b'{"data": {"alert": null}}',
    b'{"data": {"alerts": {"edges": [1, {"node": 2}, {"node": {"status": "NEW"}}]}}}',
    None, 12, ["x"], "{}",
])
def test_hostile_input_never_raises_and_never_verified(raw):
    rows = _ing(raw)
    assert rows
    for r in rows:
        _sealed(r)
        assert r["relayed_verdict"] == COULD_NOT_LOOK


def test_huge_input_is_digested_not_read():
    raw = b" " * (S.MAX_PAYLOAD_BYTES + 1)
    rows = _ing(raw)
    assert len(rows) == 1 and rows[0]["could_not_look"]["reason_word"] == "bounded"
    assert rows[0]["input_sha256"] == hashlib.sha256(raw).hexdigest()


def test_too_many_alerts_is_bounded(monkeypatch):
    monkeypatch.setattr(S, "MAX_ROWS", 3)
    rows = _ing(LIST)
    assert len(rows) == 4 and rows[-1]["could_not_look"]["reason_word"] == "bounded"


def test_bare_list_and_single_node_are_read():
    nodes = json.loads(GET)["data"]["alert"]
    assert _ing(json.dumps([nodes]).encode())[0]["relayed_verdict"] == BROKEN
    assert _ing(json.dumps(nodes).encode())[0]["relayed_verdict"] == BROKEN


def test_standing_verdict_and_rollup_never_verified():
    rows = _ing(LIST)
    for fn in (S.standing_verdict, S.rollup):
        assert fn(rows)["relayed_verdict"] == BROKEN
        clean = fn(rows[1:])
        assert clean["relayed_verdict"] == COULD_NOT_LOOK
        forged = [dict(r, relayed_verdict=VERIFIED) for r in rows[1:]]
        assert fn(forged)["relayed_verdict"] == COULD_NOT_LOOK
        assert fn([])["relayed_verdict"] == COULD_NOT_LOOK
        assert fn("junk")["relayed_verdict"] == COULD_NOT_LOOK
        assert fn(rows)["signed_by_vendor"] is False


def test_recheck_says_could_not_look():
    r = _ing(GET)[0]
    assert recheck(r, GET)["verdict"] == COULD_NOT_LOOK


def test_doc_section_has_what_this_cannot_prove():
    doc = (ROOT / "docs" / "CONNECTOR_ADAPTER.md").read_text(encoding="utf-8")
    sec = doc.split("## SentinelOne alert export", 1)[1].split("\n## ", 1)[0]
    assert "### What this cannot prove" in sec
    assert "github.com/Sentinel-One/purple-mcp" in sec
