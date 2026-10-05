# SPDX-License-Identifier: MIT
"""A06: an OPA decision-log POST body (a JSON array of decision events, usually
gzipped) becomes relayed check rows on connector.core, one per event. The
fixtures are synthetic: no real decision, no real address. No network."""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from arcaeon.connector import ROW_KIND, VendorAdapter, adapter_for, import_verdict, recheck
from arcaeon.connector import opa as O
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "opa"
PLAIN = (FIX / "decision_log.json").read_bytes()
GZ = (FIX / "decision_log.json.gz").read_bytes()
AT = "2026-10-04T12:00:00Z"
ALLOW = ("authz/allow",)
DENY = ("authz/deny",)


def _rows(raw=PLAIN, **kw):
    kw.setdefault("allow_paths", ALLOW)
    kw.setdefault("deny_paths", DENY)
    return O.ingest(raw, received_at=AT, **kw)


def _events(evts):
    return json.dumps(evts).encode()


def test_adapter_is_on_the_one_base_and_registered():
    assert isinstance(O.OPA, VendorAdapter) and O.OPA.one_row_per_payload is False
    assert adapter_for("opa") is O.OPA
    assert O.OPA.name == "opa" and O.OPA.version == "1"


def test_fixtures_are_the_same_body_plain_and_gzipped():
    assert GZ[:2] == b"\x1f\x8b"
    assert json.loads(gzip.decompress(GZ)) == json.loads(PLAIN)


def test_one_row_per_event_in_order_with_the_documented_fields():
    rows = _rows()
    evts = json.loads(PLAIN)
    assert len(rows) == len(evts)
    for i, (r, e) in enumerate(zip(rows, evts)):
        assert r["kind"] == ROW_KIND and r["relayed"] is True and r["checked_by_us"] is False
        assert "verdict" not in r
        assert r["vendor"] == {"name": "opa", "adapter_version": "1"}
        assert r["vendor_id"] == e["decision_id"]
        assert r["attestation"]["status"] == "NONE"
        d = r["decision"]
        assert d["event_index"] == i and d["timestamp"] == e["timestamp"]
        assert r["received_at"] == AT


def test_words_follow_the_declared_polarity():
    got = [(r["decision"]["path"], r["vendor_word"], r["relayed_verdict"]) for r in _rows()]
    assert got == [
        ("authz/allow", "allowed", VERIFIED),
        ("authz/allow", "denied", BROKEN),
        ("authz/deny", "denied", BROKEN),
        ("authz/deny", "allowed", VERIFIED),
        ("authz/allow", "non_boolean", COULD_NOT_LOOK),
        ("authz/allow", "undefined", COULD_NOT_LOOK),
        ("authz/allow", "masked", COULD_NOT_LOOK),
        ("reports/summary", "non_boolean", COULD_NOT_LOOK),
    ]


def test_an_undeclared_path_never_maps_a_boolean():
    rows = _rows(allow_paths=(), deny_paths=())
    assert [r["vendor_word"] for r in rows[:4]] == ["undeclared_path"] * 4
    assert all(r["relayed_verdict"] == COULD_NOT_LOOK for r in rows)
    assert all("could_not_look" in r for r in rows)


def test_a_slash_prefixed_path_is_the_same_path():
    rows = _rows(_events([{"decision_id": "d", "path": "/authz/allow", "result": True}]))
    assert rows[0]["relayed_verdict"] == VERIFIED
    rows = _rows(_events([{"decision_id": "d", "path": "authz/allow", "result": True}]),
                 allow_paths=("/authz/allow",))
    assert rows[0]["relayed_verdict"] == VERIFIED


def test_the_doc_example_string_true_is_not_a_boolean():
    rows = _rows(_events([{"decision_id": "d", "path": "authz/allow", "result": "true"}]))
    assert rows[0]["vendor_word"] == "non_boolean"
    assert rows[0]["relayed_verdict"] == COULD_NOT_LOOK


def test_gzip_body_gives_the_same_rows_but_its_own_digest():
    a, b = _rows(PLAIN), _rows(GZ)
    assert len(a) == len(b)
    for x, y in zip(a, b):
        assert y["decision"]["payload_encoding"] == "gzip"
        assert x["decision"]["payload_encoding"] == "identity"
        assert y["vendor_payload_digest"] != x["vendor_payload_digest"]
        assert y["vendor_payload_bytes"] == len(GZ)
        keep = ("vendor_id", "vendor_word", "relayed_verdict", "subject")
        assert {k: x[k] for k in keep} == {k: y[k] for k in keep}


def test_subject_is_the_path_and_the_input_digest():
    r = _rows()[0]
    e = json.loads(PLAIN)[0]
    assert r["subject"]["name"] == "opa:authz/allow"
    assert r["decision"]["input_digest"] == O.OPA.digest(e["input"])
    assert r["subject"]["sha256"] == r["decision"]["input_digest"][len("sha256:jcs:v1:"):]


def test_masked_input_is_said_and_masked_result_is_could_not_look():
    rows = _rows()
    m = rows[6]
    assert m["decision"]["erased"] == ["/result"]
    assert m["could_not_look"]["reason_word"] == "missing"
    assert rows[1]["decision"]["input_masked"] is True


def test_requested_by_and_headers_are_not_copied():
    blob = json.dumps(_rows())
    assert "requested_by" not in blob and "request_context" not in blob


@pytest.mark.parametrize("raw,why", [
    (b"", "empty"),
    (b"\x1f\x8bnot gzip at all", "unreadable"),
    (b"{\"decision_id\": \"d\"}", "name_not_found"),
    (b"[]", "empty"),
    (b"not json", "unreadable"),
    (b"[{\"a\": 1, \"a\": 2}]", "unreadable"),
    (gzip.compress(b"[]") + b"trailing", "unreadable"),
    (gzip.compress(b"[{\"path\": \"authz/allow\", \"result\": true}]")[:-6], "unreadable"),
])
def test_hostile_bodies_are_one_could_not_look_row(raw, why):
    rows = O.ingest(raw, received_at=AT, allow_paths=ALLOW)
    assert len(rows) == 1
    assert rows[0]["relayed_verdict"] == COULD_NOT_LOOK
    assert rows[0]["could_not_look"]["reason_word"] == why


def test_a_gzip_bomb_is_bounded():
    bomb = gzip.compress(b"[" + b" " * (O.MAX_BODY_BYTES + 10) + b"]")
    rows = O.ingest(bomb, received_at=AT)
    assert len(rows) == 1 and rows[0]["could_not_look"]["reason_word"] == "bounded"


def test_an_event_that_is_not_an_object_is_its_own_row():
    rows = _rows(_events([1, {"decision_id": "d", "path": "authz/allow", "result": True}]))
    assert [r["relayed_verdict"] for r in rows] == [COULD_NOT_LOOK, VERIFIED]


def test_too_many_events_are_bounded(monkeypatch):
    monkeypatch.setattr(O, "MAX_ROWS", 2)
    rows = _rows(_events([{"path": "authz/allow", "result": True}] * 3))
    assert len(rows) == 3 and rows[-1]["could_not_look"]["reason_word"] == "bounded"


def test_never_raises_on_non_bytes():
    rows = O.ingest(None, received_at=AT)
    assert rows[0]["relayed_verdict"] == COULD_NOT_LOOK


def test_a_path_in_both_lists_is_a_caller_error():
    with pytest.raises(ValueError):
        O.ingest(PLAIN, allow_paths=("authz/allow",), deny_paths=("/authz/allow",))


def test_not_rechecked_or_imported_as_one_verdict():
    rows = _rows()
    assert recheck(rows[0], PLAIN)["verdict"] == COULD_NOT_LOOK
    one = import_verdict(O.OPA, PLAIN)
    assert one["relayed_verdict"] == COULD_NOT_LOOK


# --- L2-01b: every plain ingest row says it is not signed by the vendor ---------------

@pytest.mark.parametrize("raw", [
    PLAIN, GZ, b"", b"not json", b"[]", b"{\"a\": 1}", None,
    json.dumps([1, {"decision_id": "d", "path": "authz/allow", "result": True}]).encode(),
], ids=["plain", "gzip", "empty", "not_json", "no_events", "object", "none", "bad_event"])
def test_every_ingest_row_carries_signed_by_vendor_false(raw):
    rows = O.ingest(raw, received_at=AT, allow_paths=ALLOW, deny_paths=DENY)
    assert rows
    for r in rows:
        assert "signed_by_vendor" in r and r["signed_by_vendor"] is False


def test_a_bounded_ingest_row_carries_signed_by_vendor_false(monkeypatch):
    monkeypatch.setattr(O, "MAX_ROWS", 1)
    rows = _rows(_events([{"path": "authz/allow", "result": True}] * 2))
    assert len(rows) == 2 and all(r["signed_by_vendor"] is False for r in rows)
    bomb = gzip.compress(b"[" + b" " * (O.MAX_BODY_BYTES + 10) + b"]")
    assert O.ingest(bomb, received_at=AT)[0]["signed_by_vendor"] is False
