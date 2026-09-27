"""`arcaeon schema --format claude`: the Claude tool-use file (K081).

docs/schemas/claude_tools.json is generated from the OpenAPI document, never
hand-written. Regenerate with
`py -m arcaeon schema --format claude --out docs/schemas/claude_tools.json`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from arcaeon.adapters import tool_specs
from arcaeon.schema import cli as SC
from arcaeon.serve import openapi as O

COMMITTED = Path(__file__).resolve().parents[2] / "docs" / "schemas" / "claude_tools.json"
REGEN = "py -m arcaeon schema --format claude --out docs/schemas/claude_tools.json"


def test_committed_file_matches_the_generated_one():
    raw = COMMITTED.read_bytes()
    assert b"\r\n" not in raw
    assert raw.decode("ascii") == SC.render("claude"), f"stale; run {REGEN}"


def test_shape_is_name_description_input_schema():
    tools = json.loads(COMMITTED.read_text(encoding="utf-8"))
    assert isinstance(tools, list) and tools
    assert [t["name"] for t in tools] == [s.name for s in tool_specs()]
    for t in tools:
        assert set(t) == {"name", "description", "input_schema"}
        assert re.fullmatch(r"[A-Za-z0-9_-]{1,64}", t["name"])
        assert t["input_schema"]["type"] == "object"
        assert isinstance(t["input_schema"]["properties"], dict)
        assert t["description"]
    assert "seal" not in {t["name"] for t in tools}


def test_generated_from_the_openapi_document(monkeypatch):
    doc = O.build()
    doc["paths"]["/v1/verify"]["post"]["summary"] = "EDITED IN THE DOCUMENT"
    monkeypatch.setattr(O, "build", lambda: doc)
    tools = {t["name"]: t for t in json.loads(SC.render("claude"))}
    assert "EDITED IN THE DOCUMENT" in tools["verify"]["description"]


def test_cli_prints_and_writes_the_same_text(tmp_path, capsys):
    assert SC.main(["--format", "claude"]) == 0
    printed = capsys.readouterr().out
    out = tmp_path / "c.json"
    assert SC.main(["--format", "claude", "--out", str(out)]) == 0
    assert out.read_bytes().decode("utf-8") == printed == SC.render("claude")


def test_openapi_format_is_unchanged():
    assert SC.render("openapi") == O.dumps()
