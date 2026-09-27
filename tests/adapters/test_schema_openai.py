"""`arcaeon schema --format openai`: the function-calling file (K082).

docs/schemas/openai_functions.json is generated from the OpenAPI document,
never hand-written. Regenerate with
`py -m arcaeon schema --format openai --out docs/schemas/openai_functions.json`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from arcaeon.adapters import tool_specs
from arcaeon.schema import cli as SC
from arcaeon.serve import openapi as O

COMMITTED = Path(__file__).resolve().parents[2] / "docs" / "schemas" / "openai_functions.json"
REGEN = "py -m arcaeon schema --format openai --out docs/schemas/openai_functions.json"


def test_committed_file_matches_the_generated_one():
    raw = COMMITTED.read_bytes()
    assert b"\r\n" not in raw
    assert raw.decode("ascii") == SC.render("openai"), f"stale; run {REGEN}"


def test_each_entry_is_a_function_with_parameters():
    tools = json.loads(COMMITTED.read_text(encoding="utf-8"))
    assert isinstance(tools, list) and tools
    assert [t["name"] for t in tools] == [s.name for s in tool_specs()]
    for t in tools:
        assert t["type"] == "function"
        assert set(t) == {"type", "name", "description", "parameters"}
        assert re.fullmatch(r"[A-Za-z0-9_-]{1,64}", t["name"])
        assert t["parameters"]["type"] == "object"
        assert isinstance(t["parameters"]["properties"], dict)
    assert "seal" not in {t["name"] for t in tools}


def test_same_schemas_as_the_claude_file():
    claude = {t["name"]: t["input_schema"] for t in json.loads(SC.render("claude"))}
    openai = {t["name"]: t["parameters"] for t in json.loads(SC.render("openai"))}
    assert claude == openai


def test_generated_from_the_openapi_document(monkeypatch):
    doc = O.build()
    doc["paths"]["/v1/log"]["post"]["summary"] = "EDITED IN THE DOCUMENT"
    monkeypatch.setattr(O, "build", lambda: doc)
    tools = {t["name"]: t for t in json.loads(SC.render("openai"))}
    assert "EDITED IN THE DOCUMENT" in tools["log"]["description"]
