"""The GPT Action manifest (K084).

docs/schemas/gpt_action_openapi.json is generated from the OpenAPI document,
never hand-written. Regenerate with
`py -m arcaeon schema --format gpt-action --out docs/schemas/gpt_action_openapi.json`.
"""
from __future__ import annotations

import json
from pathlib import Path

from arcaeon.adapters import tool_specs
from arcaeon.schema import cli as SC
from arcaeon.serve import openapi as O
from arcaeon.serve import routes as R

COMMITTED = Path(__file__).resolve().parents[2] / "docs" / "schemas" / "gpt_action_openapi.json"
REGEN = "py -m arcaeon schema --format gpt-action --out docs/schemas/gpt_action_openapi.json"


def _manifest() -> dict:
    return json.loads(COMMITTED.read_text(encoding="utf-8"))


def _ops(doc):
    return [(m, p, op) for p, ops in doc["paths"].items() for m, op in ops.items()]


def test_committed_file_matches_the_generated_one():
    raw = COMMITTED.read_bytes()
    assert b"\r\n" not in raw
    assert raw.decode("ascii") == SC.render("gpt-action"), f"stale; run {REGEN}"


def test_placeholder_server_and_the_description_says_so():
    m = _manifest()
    assert m["openapi"].startswith("3.1")
    assert m["servers"] == [{"url": "https://REPLACE-WITH-YOUR-PUBLIC-URL"}]
    assert "placeholder" in m["info"]["description"]
    assert "deploy decision" in m["info"]["description"]
    assert "127.0.0.1" not in json.dumps(m["servers"])


def test_free_routes_only_each_with_an_operation_id_and_at_most_30():
    m = _manifest()
    ops = _ops(m)
    assert 0 < len(ops) <= SC.GPT_ACTION_MAX_OPERATIONS == 30
    ids = [op["operationId"] for _, _, op in ops]
    assert all(ids) and len(set(ids)) == len(ids)
    assert ids == [s.name for s in tool_specs()]
    for _, _, op in ops:
        assert op["x-arcaeon-tier"] == "free"
        assert op["security"]
    paid = {r.path for r in R.ROUTES if r.tier == "paid"}
    assert paid and not paid & set(m["paths"])
    assert "seal" not in json.dumps(m)


def test_every_ref_resolves_and_no_schema_is_unused():
    m = _manifest()
    used: set = set()
    SC._refs(m["paths"], used)
    assert used == set(m["components"]["schemas"])
    assert m["components"]["securitySchemes"]["bearer"]["scheme"] == "bearer"


def test_generated_from_the_openapi_document(monkeypatch):
    doc = O.build()
    doc["paths"]["/v1/status"]["get"]["summary"] = "EDITED IN THE DOCUMENT"
    monkeypatch.setattr(O, "build", lambda: doc)
    m = json.loads(SC.render("gpt-action"))
    assert m["paths"]["/v1/status"]["get"]["summary"] == "EDITED IN THE DOCUMENT"
