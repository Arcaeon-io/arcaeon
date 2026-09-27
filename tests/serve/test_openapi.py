"""OpenAPI 3.1 from the route table (K013): GET /openapi.json and
`arcaeon schema --format openapi` are the same document, one operation per
route, bearer security, schemas under components."""
from __future__ import annotations

import http.client
import io
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from arcaeon.serve import openapi as O
from arcaeon.serve import routes as R
from arcaeon.serve import server as S

SRC = str(Path(__file__).resolve().parents[2] / "src")


def _ops(doc):
    return [(m.upper(), p, op) for p, item in doc["paths"].items() for m, op in item.items()]


def test_every_route_appears_once_and_every_doc_path_is_a_route():
    doc = O.build()
    ops = _ops(doc)
    got = sorted((m, p) for m, p, _ in ops)
    want = sorted((r.method, r.path) for r in R.ROUTES)
    assert got == want
    assert len(set(got)) == len(got)
    for m, p, _ in ops:
        assert R.find(m, p) is not None, (m, p)


def test_operation_ids_are_unique_and_named():
    ids = [op["operationId"] for _, _, op in _ops(O.build())]
    assert len(ids) == len(set(ids)) == len(R.ROUTES)
    assert O.operation_id(R.find("POST", "/v1/audit/verify")) == "audit_verify"
    assert O.operation_id(R.find("GET", "/")) == "index"
    assert O.operation_id(R.find("GET", "/openapi.json")) == "openapi"


def test_header_security_and_components():
    doc = O.build()
    assert doc["openapi"] == "3.1.0"
    assert doc["components"]["securitySchemes"]["bearer"] == {
        **doc["components"]["securitySchemes"]["bearer"], "type": "http", "scheme": "bearer"}
    schemas = doc["components"]["schemas"]
    for m, p, op in _ops(doc):
        r = R.find(m, p)
        assert op["security"] == ([] if r.open else [{"bearer": []}]), p
        assert ("401" in op["responses"]) is (not r.open), p
        ref = next(iter(op["responses"]["200"]["content"].values()))["schema"]["$ref"]
        assert schemas[ref.rsplit("/", 1)[1]] == r.response_schema
        if m == "POST":
            ref = op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
            assert schemas[ref.rsplit("/", 1)[1]] == r.request_schema
            assert "413" in op["responses"]
    assert O.build()["paths"]["/v1/seal"]["post"]["x-arcaeon-tier"] == "paid"


def test_every_ref_resolves():
    doc = O.build()
    text = json.dumps(doc)
    import re
    for name in re.findall(r'"#/components/schemas/([^"]+)"', text):
        assert name in doc["components"]["schemas"], name


def test_the_document_is_deterministic():
    assert O.dumps() == O.dumps()


def _cli(*args):
    env = {**os.environ, "PYTHONPATH": SRC, "ARCAEON_JOURNAL": "0"}
    return subprocess.run([sys.executable, "-m", "arcaeon", "schema", *args],
                          capture_output=True, text=True, encoding="utf-8", timeout=120,
                          env=env)


def test_cli_and_http_give_the_same_document(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    server = S.make_server(port=0, root=tmp_path)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    try:
        assert ready.wait(10)
        c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=30)
        c.request("GET", "/openapi.json")               # open: no token
        r = c.getresponse()
        served = json.loads(r.read())
        c.close()
        assert r.status == 200
    finally:
        server.shutdown()
        t.join(10)
    p = _cli("--format", "openapi")
    assert p.returncode == 0, p.stderr
    printed = json.loads(p.stdout)
    assert printed == served == O.build()
    assert (printed["openapi"], len(printed["paths"])) == (
        "3.1.0", len({r.path for r in R.ROUTES}))


def test_cli_out_writes_the_exact_bytes(tmp_path):
    out = tmp_path / "o.json"
    p = _cli("--out", str(out))
    assert p.returncode == 0, p.stderr
    assert out.read_bytes() == O.dumps().encode("utf-8")


def test_cli_unknown_format_is_usage():
    assert _cli("--format", "graphql").returncode == 2
