"""One tool list for all adapters (K080)."""
from __future__ import annotations

import json

from arcaeon.adapters import EXIT_NOTE, ToolSpec, tool_specs
from arcaeon.serve import openapi as O
from arcaeon.serve import routes as R


def _free_ids():
    return [O.operation_id(r) for r in R.ROUTES
            if r.tier == "free" and r.path.startswith("/v1/")]


def test_names_equal_the_free_routes_operation_ids():
    specs = tool_specs()
    assert [s.name for s in specs] == _free_ids()
    assert len({s.name for s in specs}) == len(specs)
    assert "seal" not in {s.name for s in specs}
    assert not {"health", "openapi", "index"} & {s.name for s in specs}


def test_each_spec_carries_the_route_schema_and_a_call():
    by_name = {s.name: s for s in tool_specs()}
    for r in R.ROUTES:
        oid = O.operation_id(r)
        if oid not in by_name:
            continue
        s = by_name[oid]
        assert isinstance(s, ToolSpec) and callable(s.call)
        assert (s.method, s.path) == (r.method, r.path)
        assert s.parameters["type"] == "object"
        assert r.summary in s.description and EXIT_NOTE in s.description
        if r.method == "POST":
            assert s.parameters == r.request_schema
        else:
            assert s.parameters == {"type": "object", "properties": {}}
    # a copy, never the route table's own dict
    by_name["log"].parameters["properties"]["x"] = {}
    log_route = R.find("POST", "/v1/log")
    assert log_route is not None, "no POST /v1/log route declared"
    assert "x" not in log_route.request_schema["properties"]


def test_building_the_list_does_no_io(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "nowhere"))
    specs = tool_specs()
    assert specs and not (tmp_path / "nowhere").exists()


def test_calls_run_against_a_loopback_server(served):
    specs = {s.name: s for s in tool_specs(served.client)}
    assert specs["log"].call({"ledger": "l.jsonl"}, fields={"n": 1})["exit"] == 0
    assert specs["log"].call(ledger="l.jsonl", fields={"n": 2})["exit"] == 0
    r = specs["verify"].call({"ledger": "l.jsonl"})
    assert (r["verdict"], r["rows"], r["exit"]) == ("VERIFIED", 2, 0)
    assert isinstance(specs["status"].call(), dict)
    bad = specs["verify"].call({"ledger": "../outside.jsonl"})
    assert bad["exit"] != 0 and bad.get("http_status") == 400


def test_no_server_is_could_not_look_not_a_raise(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "empty"))
    r = {s.name: s for s in tool_specs()}["verify"].call({"ledger": "x.jsonl"})
    assert (r["verdict"], r["exit"], r["reason_word"]) == ("COULD NOT LOOK", 3, "network")
    json.dumps(r)


def test_importing_the_package_imports_no_framework_and_no_server():
    import os
    import subprocess
    import sys
    from pathlib import Path
    src = str(Path(__file__).resolve().parents[2] / "src")
    probe = ("import sys, json; import arcaeon.adapters; "
             "print(json.dumps(sorted(m for m in sys.modules if m.startswith("
             "('arcaeon.serve', 'arcaeon.client', 'agents', 'langchain', 'mcp')))))")
    p = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": src}, timeout=120)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout.strip().splitlines()[-1]) == []
