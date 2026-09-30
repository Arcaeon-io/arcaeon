"""K075: `arcaeon mandate check` and POST /v1/mandate/check.

    pytest tests/test_mandate_check.py

inside 0, outside 1, could_not_look 3; --field needs no JSON quoting. The
HTTP handler runs the same verb (h_core.run_verb) and returns its --json
plus `exit`, key for key.
"""
from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon.serve import h_mandate
from _load import must_match

DOC = (Path(__file__).resolve().parents[1] / "docs" / "MANDATE_GATE.md").read_text(
    encoding="utf-8")
EXAMPLE = json.loads(must_match(r"```json\n(.*?)```", DOC, re.S).group(1))
AT = "2026-10-01T12:00:00Z"            # inside the example's window


@pytest.fixture
def example(tmp_path) -> Path:
    p = tmp_path / "docs-example.json"
    p.write_text(json.dumps(EXAMPLE), encoding="utf-8")
    return p


def _run(capsys, *argv):
    rc = cli.main(["mandate", "check", *map(str, argv)])
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_inside_is_0(capsys, example):
    rc, out, _ = _run(capsys, example, "--field", "name=place_order", "--field",
                      "total=19.00", "--field", "currency=USD", "--field",
                      "seller=acme-store", "--at", AT)
    assert rc == 0 and out.startswith("inside:")


def test_forbidden_is_outside_1_with_the_reason(capsys, example):
    rc, out, _ = _run(capsys, example, "--field", "name=refund")
    assert rc == 1
    assert out.strip() == ("outside: tool 'refund' matches forbidden_acts pattern "
                           "'refund'")


def test_over_the_cap_is_outside(capsys, example):
    rc, out, _ = _run(capsys, example, "--field", "name=place_order", "--field",
                      "total=61.00", "--field", "currency=USD", "--field",
                      "seller=acme-store", "--at", AT, "--json")
    res = json.loads(out)
    assert rc == 1 and res["verdict"] == "outside" and res["rule"] == "spend_cap"
    assert res["blocks"] is False


def test_unreadable_amount_is_could_not_look_3(capsys, example):
    rc, out, _ = _run(capsys, example, "--field", "name=place_order", "--field",
                      "total=lots", "--field", "currency=USD", "--field",
                      "seller=acme-store", "--at", AT, "--json")
    res = json.loads(out)
    assert rc == 3 and res["verdict"] == "could_not_look"
    assert res["reason_word"] == "unreadable" and res["looked_for"]


def test_missing_mandate_is_could_not_look_3(capsys, tmp_path):
    rc, out, _ = _run(capsys, tmp_path / "absent.json", "--field", "name=echo", "--json")
    res = json.loads(out)
    assert rc == 3 and res["mandate_status"] == "missing"
    assert res["reason_word"] == "missing"


def test_no_name_is_usage_2(capsys, example):
    rc, _, err = _run(capsys, example, "--field", "total=1")
    assert rc == 2 and "name=" in err


def test_bad_field_is_usage_2(capsys, example):
    rc, _, err = _run(capsys, example, "--field", "nokey")
    assert rc == 2 and "KEY=VALUE" in err


def test_spent_counts_toward_the_session_total(capsys, tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"spend_cap": {"amount": "60", "total": "100",
                                           "currency": "USD"}}), encoding="utf-8")
    base = ["--field", "name=buy", "--field", "total=30", "--field", "currency=USD"]
    assert _run(capsys, p, *base, "--spent", "70")[0] == 0
    rc, out, _ = _run(capsys, p, *base, "--spent", "71", "--json")
    res = json.loads(out)
    assert rc == 1 and res["rule"] == "spend_cap.total"
    assert res["evt"] == "mandate_cap_exceeded"


def test_typed_field(capsys, example):
    # total:=19 is an integer amount the deal lane reads; still inside
    rc, _, _ = _run(capsys, example, "--field", "name=place_order", "--field", "total:=19",
                    "--field", "currency=USD", "--field", "seller=acme-store", "--at", AT)
    assert rc == 0


def test_check_writes_nothing(capsys, example, tmp_path):
    before = sorted(x.name for x in tmp_path.iterdir())
    _run(capsys, example, "--field", "name=refund")
    assert sorted(x.name for x in tmp_path.iterdir()) == before


# -- POST /v1/mandate/check ---------------------------------------------------

def test_route_names_this_handler():
    from arcaeon.serve import routes
    r = next(x for x in routes.ROUTES if x.path == "/v1/mandate/check")
    mod, fn = r.handler.split(":")
    assert getattr(importlib.import_module(mod), fn) is h_mandate.check


def test_handler_matches_the_cli_key_for_key(capsys, example):
    fields = {"name": "refund"}
    got = h_mandate.check({"mandate": str(example), "fields": fields})
    rc, out, _ = _run(capsys, example, "--field", "name=refund", "--json")
    assert got == {**json.loads(out), "exit": rc}
    assert got["exit"] == 1 and got["verdict"] == "outside"


def test_handler_inside_and_could_not_look(example, tmp_path):
    ok = h_mandate.check({"mandate": str(example), "at": AT, "fields": {
        "name": "place_order", "total": "19.00", "currency": "USD", "seller": "acme-store"}})
    assert ok["exit"] == 0 and ok["verdict"] == "inside"
    gone = h_mandate.check({"mandate": str(tmp_path / "absent.json"),
                            "fields": {"name": "echo"}})
    assert gone["exit"] == 3 and gone["verdict"] == "could_not_look"


def test_handler_keeps_json_types(example):
    # 19.5 as a JSON number is not an amount string: the gate says so (3),
    # it is never quietly turned into "19.5" and passed.
    res = h_mandate.check({"mandate": str(example), "at": AT, "fields": {
        "name": "place_order", "total": 19.5, "currency": "USD", "seller": "acme-store"}})
    assert res["exit"] == 3


@pytest.mark.parametrize("body,word", [
    ([], "JSON object"),
    ({}, "'mandate'"),
    ({"mandate": "m.json", "fields": []}, "`fields`"),
    ({"mandate": "m.json", "fields": {"a=b": "1"}}, "cannot be passed"),
    ({"mandate": "m.json", "fields": {"name": "x"}, "at": 5}, "`at`"),
])
def test_handler_bad_bodies_are_usage(body, word):
    res = h_mandate.check(body)
    assert res["exit"] == 2 and word in res["error"]
