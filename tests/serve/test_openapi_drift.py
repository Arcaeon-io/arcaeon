"""docs/openapi.json is the built document, byte for byte (K014).

Regenerate with `py -m arcaeon schema --format openapi --out docs/openapi.json`.
A drift names every path whose operations changed, so the failure says which
route moved rather than that the file differs somewhere.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from arcaeon.serve import openapi as O
from arcaeon.serve import routes as R

COMMITTED = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"
REGEN = "py -m arcaeon schema --format openapi --out docs/openapi.json"


def drift(committed: dict, built: dict) -> list[str]:
    """What differs: each changed path, then any other top-level section."""
    out = []
    a, b = committed.get("paths", {}), built.get("paths", {})
    for p in sorted(set(a) | set(b)):
        if a.get(p) != b.get(p):
            out.append(p)
    for k in sorted(set(committed) | set(built)):
        if k != "paths" and committed.get(k) != built.get(k):
            out.append(k)
    return out


def check(committed_text: str) -> None:
    built_text = O.dumps()
    if committed_text == built_text:
        return
    changed = drift(json.loads(committed_text), json.loads(built_text)) or ["(formatting)"]
    raise AssertionError(f"docs/openapi.json is stale at {', '.join(changed)}; run {REGEN}")


def test_committed_document_matches_the_route_table():
    check(COMMITTED.read_bytes().decode("utf-8"))


def test_a_changed_summary_fails_naming_the_path(monkeypatch):
    committed = COMMITTED.read_bytes().decode("utf-8")
    target = R.find("POST", "/v1/audit/verify")
    swapped = tuple(dataclasses.replace(r, summary=r.summary + " (edited)") if r is target
                    else r for r in R.ROUTES)
    monkeypatch.setattr(R, "ROUTES", swapped)
    with pytest.raises(AssertionError) as e:
        check(committed)
    assert "/v1/audit/verify" in str(e.value)
    assert drift(json.loads(committed), O.build()) == ["/v1/audit/verify"]


def test_the_committed_file_is_lf_and_ascii():
    raw = COMMITTED.read_bytes()
    assert b"\r\n" not in raw
    raw.decode("ascii")
