"""K074: `arcaeon mandate lint` and `arcaeon mandate explain`, on the
docs/MANDATE_GATE.md example.

    pytest tests/test_mandate_cli.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon.record import mandate_cli as mc
from _load import must_match

DOC = (Path(__file__).resolve().parents[1] / "docs" / "MANDATE_GATE.md").read_text(
    encoding="utf-8")
#: The first ```json block in the doc: the mandate example.
EXAMPLE = json.loads(must_match(r"```json\n(.*?)```", DOC, re.S).group(1))


@pytest.fixture
def example(tmp_path) -> Path:
    p = tmp_path / "mandate.json"
    p.write_text(json.dumps(EXAMPLE, indent=1), encoding="utf-8")
    return p


def _write(tmp_path, obj, name="m.json") -> Path:
    p = tmp_path / name
    p.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")
    return p


def _run(capsys, *argv):
    rc = cli.main(["mandate", *map(str, argv)])
    out = capsys.readouterr()
    return rc, out.out, out.err


# -- lint ---------------------------------------------------------------------

def test_lint_the_doc_example_is_valid(capsys, example):
    rc, out, _ = _run(capsys, "lint", example)
    assert rc == 0, out
    assert "valid" in out and "invalid" not in out


def test_lint_json_names_shape_and_hash(capsys, example):
    rc, out, _ = _run(capsys, "lint", example, "--json")
    res = json.loads(out)
    assert rc == 0 and res["valid"] is True and res["shape"] == "tool"
    assert res["problems"] == [] and len(res["file_sha256"]) == 64


def test_lint_names_an_unknown_key_and_exits_2(capsys, tmp_path):
    p = _write(tmp_path, dict(EXAMPLE, alowed_acts=["x"]))
    rc, out, _ = _run(capsys, "lint", p)
    assert rc == 2
    assert "'alowed_acts' is not a mandate field" in out


def test_lint_names_an_unknown_spend_cap_key(capsys, tmp_path):
    p = _write(tmp_path, dict(EXAMPLE, spend_cap={"amount": "5", "limit": "9"}))
    rc, out, _ = _run(capsys, "lint", p, "--json")
    res = json.loads(out)
    assert rc == 2 and [x["key"] for x in res["problems"]] == ["spend_cap.limit"]


@pytest.mark.parametrize("field,value,word", [
    ("allowed_acts", "search_*", "a list of strings"),
    ("forbidden_acts", ["ok", 3], "a list of strings"),
    ("who", 7, "a string"),
    ("not_after", "next tuesday", "an ISO 8601 time string"),
    ("spend_cap", "60.00", "an object"),
])
def test_lint_names_bad_types(capsys, tmp_path, field, value, word):
    p = _write(tmp_path, dict(EXAMPLE, **{field: value}))
    rc, out, _ = _run(capsys, "lint", p)
    assert rc == 2
    assert f"'{field}' must be {word}" in out


def test_lint_float_amount_is_a_bad_type(capsys, tmp_path):
    p = _write(tmp_path, dict(EXAMPLE, spend_cap={"amount": 60.5, "currency": "USD"}))
    rc, out, _ = _run(capsys, "lint", p)
    assert rc == 2 and "'spend_cap.amount' must be an amount written as a string" in out


def test_lint_not_json_is_invalid(capsys, tmp_path):
    rc, out, _ = _run(capsys, "lint", _write(tmp_path, "{nope"))
    assert rc == 2 and "not JSON" in out


def test_lint_missing_file_is_could_not_look(capsys, tmp_path):
    rc, out, _ = _run(capsys, "lint", tmp_path / "absent.json", "--json")
    res = json.loads(out)
    assert rc == 3 and res["verdict"] == "COULD_NOT_LOOK"
    assert res["reason_word"] == "missing" and res["looked_for"] == "the mandate"


def test_lint_accepts_the_deal_lane_body_and_sidecar(capsys, tmp_path):
    body = {"merchant": "acme-store", "cap": "60.00", "currency": "USD",
            "not_before": None, "not_after": None, "may": ["place_order"], "may_not": []}
    rc, out, _ = _run(capsys, "lint", _write(tmp_path, body), "--json")
    assert rc == 0 and json.loads(out)["shape"] == "deal"
    side = {"deal": "d-1", "mandate_digest": "sha256:json-c14n:v1:00", "mandate": body}
    rc, out, _ = _run(capsys, "lint", _write(tmp_path, side, "s.json"), "--json")
    assert rc == 0 and json.loads(out)["shape"] == "sealed"
    side["mandate"] = dict(body, extra=1)
    rc, out, _ = _run(capsys, "lint", _write(tmp_path, side, "s2.json"), "--json")
    assert rc == 2 and json.loads(out)["problems"][0]["key"] == "mandate.extra"


def test_lint_warns_on_a_shadowed_alias(capsys, tmp_path):
    p = _write(tmp_path, dict(EXAMPLE, may=["x"]))
    rc, out, _ = _run(capsys, "lint", p)
    assert rc == 0 and "ignores may" in out


def test_lint_and_the_gate_agree(tmp_path):
    """Every file lint passes, the gate loads."""
    from arcaeon.record.adapter import mandate_gate
    for obj in (EXAMPLE, {}, {"spend_cap": {"total": "100"}}, {"may": ["a"], "cap": "1"}):
        p = _write(tmp_path, obj)
        assert mc.lint(obj)["valid"] is True
        assert mandate_gate.load(p).ok


# -- explain ------------------------------------------------------------------

def test_explain_the_doc_example(capsys, example):
    rc, out, _ = _run(capsys, "explain", example)
    assert rc == 0
    assert "This agent may call search_*, get_quote and place_order." in out
    assert "It may not call delete_* or refund" in out
    assert "One call may spend at most 60.00 USD, and only with acme-store." in out
    assert "from 2026-09-01T00:00:00Z until 2026-12-31T23:59:59Z" in out
    assert "purchasing-agent@acme" in out
    assert "Record-only unless the proxy is started with --mandate-enforce" in out


def test_explain_an_empty_mandate_constrains_nothing(capsys, tmp_path):
    rc, out, _ = _run(capsys, "explain", _write(tmp_path, {}))
    assert rc == 0
    assert "may call any tool that is not forbidden" in out
    assert "It sets no spend cap." in out and "It sets no time window." in out


def test_explain_names_the_session_total(capsys, tmp_path):
    p = _write(tmp_path, {"spend_cap": {"amount": "10", "total": "100", "currency": "USD"}})
    rc, out, _ = _run(capsys, "explain", p)
    assert rc == 0 and "The whole session may spend at most 100 USD" in out


def test_explain_json(capsys, example):
    rc, out, _ = _run(capsys, "explain", example, "--json")
    res = json.loads(out)
    assert rc == 0 and any("place_order" in s for s in res["sentences"])


def test_explain_an_invalid_mandate_exits_2(capsys, tmp_path):
    rc, _, err = _run(capsys, "explain", _write(tmp_path, {"bogus": 1}))
    assert rc == 2 and "'bogus' is not a mandate field" in err


def test_explain_missing_file_is_could_not_look(capsys, tmp_path):
    rc, _, err = _run(capsys, "explain", tmp_path / "absent.json")
    assert rc == 3 and "COULD NOT LOOK" in err


def test_no_subcommand_is_usage(capsys):
    rc, _, _ = _run(capsys)
    assert rc == 2
