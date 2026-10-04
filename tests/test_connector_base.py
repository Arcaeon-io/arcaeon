# SPDX-License-Identifier: MIT
"""D069: one adapter base class (arcaeon.connector.core.VendorAdapter) under both
the mock vendor (D011) and the mcp-scan adapter (D060), one digest function."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from arcaeon.connector import (JCS_DIGEST_PREFIX, ROW_KIND, VendorAdapter, adapter_for,
                               import_verdict, jcs_digest, recheck)
from arcaeon.connector.mockscan import MOCKSCAN, MockScanAdapter
from arcaeon.prove import jcs
from arcaeon.prove import mcp_scan as M
from arcaeon.verdict import COULD_NOT_LOOK

ROOT = Path(__file__).resolve().parents[1]
V05 = (ROOT / "tests" / "fixtures" / "mcp_scan" / "v05_scan.json").read_bytes()


def test_both_adapters_subclass_the_one_base():
    assert issubclass(MockScanAdapter, VendorAdapter)
    assert issubclass(M.McpScanAdapter, VendorAdapter)
    assert isinstance(MOCKSCAN, VendorAdapter) and isinstance(M.MCP_SCAN, VendorAdapter)
    assert adapter_for("mockscan") is MOCKSCAN
    assert adapter_for("mcp-scan") is M.MCP_SCAN


@pytest.mark.parametrize("value", [
    {"name": "get_weather", "description": "Weather.", "inputSchema": {"type": "object"}},
    {"b": [1, 2.5, None, True], "a": "é"},
    "plain",
    [],
])
def test_same_canonical_input_same_digest(value):
    reordered = json.loads(json.dumps(value, sort_keys=True)) if isinstance(value, dict) else value
    want = JCS_DIGEST_PREFIX + jcs.sha256_hex(value)
    assert MOCKSCAN.digest(value) == M.MCP_SCAN.digest(value) == jcs_digest(value) == want
    assert MOCKSCAN.digest(reordered) == M.MCP_SCAN.digest(value)
    assert want.startswith("sha256:jcs:v1:") and len(want) == len("sha256:jcs:v1:") + 64


def test_mcp_scan_tool_digest_is_the_base_digest():
    tool = {"inputSchema": {"type": "object"}, "description": "d", "name": "t", "title": "x"}
    got, _ = M.tool_digest(tool)
    assert got == MOCKSCAN.digest({"name": "t", "description": "d",
                                   "inputSchema": {"type": "object"}})


def test_base_row_is_shared_unsigned_and_never_verified():
    a = MOCKSCAN.base_row(b"{}", "2026-10-04T12:00:00Z")
    b = M.MCP_SCAN.base_row(b"{}", "2026-10-04T12:00:00Z")
    assert set(a) == set(b)
    for r in (a, b):
        assert r["kind"] == ROW_KIND and r["relayed"] is True and r["checked_by_us"] is False
        assert r["attestation"] == {"status": "NONE", "checked_by_us": False, "claimed": None}
        assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert {k: v for k, v in a.items() if k != "vendor"} == \
        {k: v for k, v in b.items() if k != "vendor"}
    assert b["vendor"] == {"name": "mcp-scan", "adapter_version": "1"}


def test_mcp_scan_rows_are_not_rechecked_or_imported_as_one_verdict():
    rows = M.ingest(V05, received_at="2026-10-04T12:00:00Z")
    assert rows and all(r["vendor"]["name"] == "mcp-scan" for r in rows)
    out = recheck(rows[0], V05)
    assert out["verdict"] == COULD_NOT_LOOK
    one = import_verdict(M.MCP_SCAN, V05)
    assert one["relayed_verdict"] == COULD_NOT_LOOK and one["mapping"]["rule"] == "not_read"


def test_the_digest_scheme_is_defined_in_one_place():
    formula = '"sha256:jcs:v1:" + hex('
    hits = [p.relative_to(ROOT).as_posix()
            for p in list((ROOT / "docs").glob("*.md")) + list((ROOT / "src").rglob("*.py"))
            if formula in p.read_text(encoding="utf-8")]
    assert hits == ["docs/CONNECTOR_ADAPTER.md"]
    doc = (ROOT / "docs" / "CONNECTOR_ADAPTER.md").read_text(encoding="utf-8")
    assert doc.count(formula) == 1 and "## The sha256:jcs:v1 digest" in doc
