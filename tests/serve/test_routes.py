"""The route table (K002): one list, every route in section 0, both schemas on
every row, and a stdlib validator that names the field it rejects."""
from __future__ import annotations

import pytest

from arcaeon.serve import routes as R
from arcaeon.serve import schema_check as S


def _route(method: str, path: str) -> R.Route:
    """R.find that fails naming the method and path, not on None later."""
    r = R.find(method, path)
    assert r is not None, f"no route for {method} {path}"
    return r

#: Section 0 of BATCH_OPUS_2026-09-27_PLUGIN.md, verbatim (handshake as its
#: three KH7 paths).
SECTION_0 = [
    ("GET", "/health"), ("GET", "/openapi.json"), ("GET", "/"),
    ("POST", "/v1/log"), ("POST", "/v1/verify"), ("POST", "/v1/reconcile"),
    ("POST", "/v1/audit/verify"), ("POST", "/v1/audit/export"),
    ("POST", "/v1/receipt/verify"), ("GET", "/v1/status"), ("POST", "/v1/pin"),
    ("POST", "/v1/seal"), ("POST", "/v1/evidence-pack"),
    ("POST", "/v1/evidence-pack/verify"), ("POST", "/v1/export/aat"),
    ("POST", "/v1/mandate/check"), ("POST", "/v1/readings"),
    ("POST", "/v1/second-read/compare"), ("POST", "/v1/handshake/propose"),
    ("POST", "/v1/handshake/accept"), ("POST", "/v1/handshake/verify"),
]


def test_the_table_is_section_0_exactly_once_each():
    got = [(r.method, r.path) for r in R.ROUTES]
    assert sorted(got) == sorted(SECTION_0)
    assert len(got) == len(set(got))


def test_everything_but_the_first_three_is_under_v1():
    for r in R.ROUTES:
        if r.path not in ("/health", "/openapi.json", "/"):
            assert r.path.startswith("/v1/"), r.path


@pytest.mark.parametrize("route", R.ROUTES, ids=lambda r: f"{r.method} {r.path}")
def test_every_route_has_both_schemas_and_a_well_formed_row(route):
    assert isinstance(route.request_schema, dict) and route.request_schema.get("type")
    assert isinstance(route.response_schema, dict) and route.response_schema.get("type")
    assert route.method in R.METHODS
    assert route.tier in ("free", "paid")
    mod, sep, fn = route.handler.partition(":")
    assert sep and mod.startswith("arcaeon.serve.") and fn.isidentifier(), route.handler
    assert route.summary.strip()
    # a tool or a stated reason, never both, never neither
    assert (route.mcp_tool is None) != (route.mcp_exempt_reason is None), route.path
    if route.method == "GET":
        assert route.request_schema == {"type": "object", "properties": {}}


@pytest.mark.parametrize("route", R.ROUTES, ids=lambda r: f"{r.method} {r.path}")
def test_every_verdict_response_carries_an_integer_exit(route):
    if route.path in ("/health", "/openapi.json", "/"):
        return
    rs = route.response_schema
    assert "exit" in rs["required"]
    assert rs["properties"]["exit"]["type"] == "integer"


def test_only_seal_is_paid_and_only_health_and_openapi_are_open():
    assert [r.path for r in R.ROUTES if r.tier == "paid"] == ["/v1/seal"]
    assert sorted(r.path for r in R.ROUTES if r.open) == ["/health", "/openapi.json"]


def test_find_and_methods_for():
    assert _route("POST", "/v1/verify").handler == "arcaeon.serve.h_record:verify"
    assert R.find("GET", "/v1/verify") is None
    assert R.methods_for("/v1/verify") == ["POST"]
    assert R.methods_for("/nope") == []


def test_no_overclaim_words_in_any_summary():
    for r in R.ROUTES:
        low = r.summary.lower()
        for bad in ("tamper-proof", "independent witness", "compliant", "truth"):
            assert bad not in low, (r.path, bad)


# --- the validator -----------------------------------------------------------

def test_validator_rejects_a_missing_required_field_by_name():
    msg = R.validate(_route("POST", "/v1/log"),{"fields": {"a": 1}})
    assert msg is not None and "'ledger'" in msg


@pytest.mark.parametrize("route", [r for r in R.ROUTES if r.request_schema.get("required")],
                         ids=lambda r: r.path)
def test_every_required_field_is_named_when_missing(route):
    for name in route.request_schema["required"]:
        body = {k: _sample(route.request_schema["properties"][k])
                for k in route.request_schema["required"] if k != name}
        msg = R.validate(route, body)
        assert msg == f"missing required field '{name}' in body", (route.path, msg)


def _sample(schema):
    t = schema["type"]
    t = t[0] if isinstance(t, list) else t
    if "enum" in schema:
        return schema["enum"][0]
    return {"string": "x", "object": {}, "boolean": True, "integer": 1}[t]


def test_validator_type_enum_maxlength_and_nesting():
    schema = {"type": "object", "required": ["a"],
              "properties": {"a": {"type": "string", "maxLength": 3},
                             "k": {"type": "string", "enum": ["tapes", "readings"]},
                             "n": {"type": "integer"},
                             "o": {"type": "object", "required": ["z"],
                                   "properties": {"z": {"type": "boolean"}}},
                             "l": {"type": "array", "items": {"type": "integer"}}}}
    assert S.first_problem(schema, {"a": "abc"}) is None
    assert S.first_problem(schema, []) == "body must be object, got array"
    assert "over the limit of 3" in (S.first_problem(schema, {"a": "abcd"}) or "")
    assert "body.k must be one of" in (S.first_problem(schema, {"a": "x", "k": "zzz"}) or "")
    assert S.first_problem(schema, {"a": "x", "n": True}) == "body.n must be integer, got boolean"
    assert S.first_problem(schema, {"a": "x", "o": {}}) == "missing required field 'z' in body.o"
    assert S.first_problem(schema, {"a": "x", "l": [1, "2"]}) == "body.l[1] must be integer, got string"
    assert S.first_problem({"type": ["string", "null"]}, None) is None


def test_validator_passes_unknown_fields_through():
    assert S.first_problem({"type": "object", "properties": {}}, {"extra": 1}) is None


def test_validator_refuses_a_schema_with_an_unknown_type():
    with pytest.raises(ValueError):
        S.problems({"type": "strng"}, "x")



def test_importing_the_table_pulls_in_no_handler():
    """A fresh interpreter: importing routes loads no handler module."""
    import subprocess
    import sys
    code = ("import sys; from arcaeon.serve import routes as R; "
            "print(sorted({r.handler.split(':')[0] for r in R.ROUTES} & set(sys.modules)))")
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == "[]"


def test_evidence_pack_verify_takes_witness_and_remote_and_aat_needs_out():
    """Lane D (K060, K061): verify_pack(pack, witness=, remote=) and
    export_aat(ledger, out); the route schemas carry the same fields."""
    r = _route("POST", "/v1/evidence-pack/verify")
    assert {"pack", "witness", "remote"} <= set(r.request_schema["properties"])
    assert R.validate(r, {"pack": "p", "remote": "yes"}) is not None
    assert R.validate(r, {"pack": "p", "witness": "w.jsonl", "remote": True}) is None
    aat = _route("POST", "/v1/export/aat")
    assert "'out'" in (R.validate(aat, {"ledger": "l.jsonl"}) or "")
