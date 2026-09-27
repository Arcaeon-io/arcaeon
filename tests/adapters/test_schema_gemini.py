"""`arcaeon schema --format gemini`: function declarations (K083).

docs/schemas/gemini_functions.json is generated from the OpenAPI document,
never hand-written. Regenerate with
`py -m arcaeon schema --format gemini --out docs/schemas/gemini_functions.json`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from arcaeon.adapters import tool_specs
from arcaeon.schema import cli as SC
from arcaeon.serve import openapi as O

COMMITTED = Path(__file__).resolve().parents[2] / "docs" / "schemas" / "gemini_functions.json"
REGEN = "py -m arcaeon schema --format gemini --out docs/schemas/gemini_functions.json"
TYPES = {"string", "number", "integer", "boolean", "array", "object"}


def _walk(node, where):
    assert set(node) <= SC.GEMINI_SCHEMA_KEYS, (where, set(node) - SC.GEMINI_SCHEMA_KEYS)
    assert node["type"] in TYPES, where
    if "required" in node:
        assert node["required"] and set(node["required"]) <= set(node.get("properties", {}))
    for name, sub in node.get("properties", {}).items():
        _walk(sub, f"{where}.{name}")
    if "items" in node:
        _walk(node["items"], f"{where}[]")


def test_committed_file_matches_the_generated_one():
    raw = COMMITTED.read_bytes()
    assert b"\r\n" not in raw
    assert raw.decode("ascii") == SC.render("gemini"), f"stale; run {REGEN}"


def test_every_declaration_is_in_the_gemini_subset():
    decls = json.loads(COMMITTED.read_text(encoding="utf-8"))
    specs = tool_specs()
    assert [d["name"] for d in decls] == [s.name for s in specs]
    for d, s in zip(decls, specs):
        assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", d["name"])
        assert d["description"]
        if s.parameters["properties"]:
            assert set(d) == {"name", "description", "parameters"}
            assert d["parameters"]["type"] == "object"
            assert set(d["parameters"]["properties"]) == set(s.parameters["properties"])
            _walk(d["parameters"], d["name"])
        else:
            assert set(d) == {"name", "description"}, d["name"]
    assert "seal" not in {d["name"] for d in decls}
    assert "parameters" not in {d["name"]: d for d in decls}["status"]


def test_a_null_type_becomes_nullable():
    got = SC.gemini_schema({"type": ["string", "null"], "description": "x", "$id": "y"})
    assert got == {"type": "string", "nullable": True, "description": "x"}


def test_generated_from_the_openapi_document(monkeypatch):
    doc = O.build()
    doc["paths"]["/v1/pin"]["post"]["summary"] = "EDITED IN THE DOCUMENT"
    monkeypatch.setattr(O, "build", lambda: doc)
    decls = {d["name"]: d for d in json.loads(SC.render("gemini"))}
    assert "EDITED IN THE DOCUMENT" in decls["pin"]["description"]
