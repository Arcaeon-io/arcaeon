# SPDX-License-Identifier: MIT
"""The OpenAPI 3.1 document for `arcaeon serve`, built from the route table (K013).

`document()` is both `GET /openapi.json` and `arcaeon schema --format
openapi`, so the two cannot disagree. One operation per route, each with an
`operationId` taken from its path, the route's own request and response
schemas under `components.schemas`, and the bearer security scheme on
every route but the open ones (/health, /openapi.json). The output is
deterministic: the same checkout gives the same bytes (docs/openapi.json,
K014, is held to it by a drift test).

The server URL named is the default one (127.0.0.1 and DEFAULT_PORT); a
client that started serve on another port uses the address it fetched from.
"""
from __future__ import annotations

import json
import re

from arcaeon.serve import DEFAULT_PORT
from arcaeon.serve import routes as R

OPENAPI_VERSION = "3.1.0"
SECURITY_SCHEME = "bearer"

_ERROR = {"type": "object", "required": ["error"],
          "properties": {"error": {"type": "string"},
                         "exit": {"type": "integer", "enum": [2]}}}
_STATUS_TEXT = {
    "400": "bad usage: not JSON, a field the schema refuses, a path outside the served root",
    "401": "no token, or the wrong one",
    "404": "no such route, or declared but not built in this checkout",
    "413": "the body is over 10 MB",
}


def operation_id(route: R.Route) -> str:
    """`/v1/audit/verify` -> `audit_verify`; `/` -> `index`."""
    p = route.path
    if p.startswith("/v1/"):
        p = p[4:]
    p = re.sub(r"\.json$", "", p.strip("/"))
    return re.sub(r"[^A-Za-z0-9]+", "_", p).strip("_") or "index"


def _version() -> str:
    try:
        from arcaeon import __version__
        return str(__version__)
    except ImportError:
        return "0"


def _operation(route: R.Route, schemas: dict) -> dict:
    oid = operation_id(route)
    html = route.response_schema.get("type") == "string"
    ok_type = "text/html" if html else "application/json"
    schemas[f"{oid}_response"] = route.response_schema
    op: dict = {
        "operationId": oid,
        "summary": route.summary,
        "x-arcaeon-tier": route.tier,
    }
    if route.mcp_tool:
        op["x-arcaeon-mcp-tool"] = route.mcp_tool
    if route.method == "POST":
        schemas[f"{oid}_request"] = route.request_schema
        op["requestBody"] = {"required": True, "content": {"application/json": {
            "schema": {"$ref": f"#/components/schemas/{oid}_request"}}}}
    responses: dict = {"200": {
        "description": "a verdict was reached (any verdict: it rides in the body, never "
                       "in the status)" if not html and route.path.startswith("/v1/")
        else "ok",
        "content": {ok_type: {"schema": {"$ref": f"#/components/schemas/{oid}_response"}}}}}
    codes = ["400", "404"] if route.open else ["400", "401", "404"]
    if route.method == "POST":
        codes.append("413")
    for c in codes:
        responses[c] = {"description": _STATUS_TEXT[c], "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Error"}}}}
    op["responses"] = responses
    op["security"] = [] if route.open else [{SECURITY_SCHEME: []}]
    return op


def build() -> dict:
    """The document, from routes.ROUTES."""
    paths: dict = {}
    schemas: dict = {"Error": _ERROR}
    for route in R.ROUTES:
        paths.setdefault(route.path, {})[route.method.lower()] = _operation(route, schemas)
    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": "arcaeon serve",
            "version": _version(),
            "description": "The local HTTP/JSON API of arcaeon: one route per check, each "
                           "answering the CLI's --json plus an integer exit (0 good, 1 a "
                           "bad finding, 2 bad usage, 3 COULD NOT LOOK). Loopback only.",
        },
        "servers": [{"url": f"http://127.0.0.1:{DEFAULT_PORT}"}],
        "security": [{SECURITY_SCHEME: []}],
        "paths": paths,
        "components": {
            "securitySchemes": {SECURITY_SCHEME: {
                "type": "http", "scheme": "bearer",
                "description": "the token in ~/.arcaeon/serve.token "
                               "(`arcaeon serve --print-token`); X-Arcaeon-Token also works"}},
            "schemas": schemas,
        },
    }


def document(body: dict | None = None) -> dict:
    """GET /openapi.json."""
    return build()


def dumps(doc: dict | None = None) -> str:
    """The document as text, the exact bytes docs/openapi.json holds."""
    return json.dumps(build() if doc is None else doc, indent=1, ensure_ascii=True) + "\n"
