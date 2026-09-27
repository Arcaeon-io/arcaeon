# SPDX-License-Identifier: MIT
"""arcaeon.adapters: one tool list, every agent framework (K080).

    from arcaeon.adapters import tool_specs
    for spec in tool_specs():
        spec.name, spec.description, spec.parameters   # JSON schema
        spec.call({"ledger": "calls.jsonl"})           # the server's JSON, a dict

`tool_specs(client=None)` reads the OpenAPI document `arcaeon serve` answers
(arcaeon.serve.openapi, itself built from the route table), so the tools, the
committed docs/openapi.json and the server's dispatch cannot disagree. One
spec per FREE check route: every operation under /v1/ whose `x-arcaeon-tier`
is `free`. The paid lane (/v1/seal) is never a tool an agent could call by
surprise; /health, /openapi.json and the dashboard describe the server
itself and are not checks, so they are not tools either.

Each spec's `call` goes through arcaeon.client.Client: a server that cannot
be reached is COULD NOT LOOK, exit 3, returned as a dict, never raised. With
no client given, a Client() is made on the first call (it reads serve.json
and serve.token then), so building the list does no I/O.

The framework adapters (arcaeon.adapters.openai_agents and the rest) wrap
these specs. No framework is imported here or at any adapter's module top:
each adapter imports its framework inside the function that needs it.
Stdlib only.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = ["ToolSpec", "tool_specs", "free_operations", "EXIT_NOTE"]

#: Appended to every description, so a model reading only the tool list
#: knows the verdict rides in the body and COULD NOT LOOK is not a pass.
EXIT_NOTE = ("Returns JSON with an integer `exit`: 0 good, 1 a bad finding, "
             "2 bad usage, 3 COULD NOT LOOK (not a pass).")

_EMPTY = {"type": "object", "properties": {}}


@dataclass(frozen=True)
class ToolSpec:
    """One free route as a tool: what a framework needs to offer it."""
    name: str                          # the route's operationId
    description: str
    parameters: dict                   # JSON schema, type object
    method: str                        # "GET" | "POST"
    path: str                          # "/v1/verify"
    call: Callable[..., dict] = field(repr=False, compare=False)


def _resolve(schema: Any, doc: dict) -> dict:
    """A request schema with its `$ref` into components followed (one level;
    the route table writes no nested refs)."""
    if isinstance(schema, dict) and "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        schema = doc["components"]["schemas"][name]
    return copy.deepcopy(schema) if isinstance(schema, dict) else dict(_EMPTY)


def free_operations(doc: dict | None = None) -> list[tuple[str, str, dict]]:
    """(METHOD, path, operation) for every free check route, in document order."""
    if doc is None:
        from arcaeon.serve import openapi
        doc = openapi.build()
    out = []
    for path, ops in doc.get("paths", {}).items():
        if not path.startswith("/v1/"):
            continue
        for method, op in ops.items():
            if op.get("x-arcaeon-tier", "free") == "free":
                out.append((method.upper(), path, op))
    return out


def _caller(method: str, path: str, holder: dict):
    def call(args: dict | None = None, **fields) -> dict:
        if holder.get("client") is None:
            from arcaeon.client import Client
            holder["client"] = Client()
        body = {**(args or {}), **fields}
        return holder["client"].call(method, path, body if method == "POST" else None)
    return call


def tool_specs(client=None, doc: dict | None = None) -> list[ToolSpec]:
    """One ToolSpec per free check route, from the OpenAPI document.

    `client`: an arcaeon.client.Client (or anything with its `call(method,
    path, body)`); None makes a default Client on the first call.
    `doc`: an OpenAPI document; None builds the one `arcaeon serve` answers."""
    if doc is None:
        from arcaeon.serve import openapi
        doc = openapi.build()
    holder = {"client": client}
    specs = []
    for method, path, op in free_operations(doc):
        body = op.get("requestBody", {}).get("content", {}).get("application/json", {})
        params = _resolve(body.get("schema"), doc) if body else dict(_EMPTY)
        params.setdefault("type", "object")
        params.setdefault("properties", {})
        summary = op.get("summary") or op["operationId"]
        specs.append(ToolSpec(
            name=op["operationId"],
            description=f"arcaeon: {summary}. {EXIT_NOTE}",
            parameters=params,
            method=method,
            path=path,
            call=_caller(method, path, holder),
        ))
    return specs
