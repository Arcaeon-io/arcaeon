# SPDX-License-Identifier: MIT
"""A pydantic arguments model per tool, derived from its JSON schema.

LlamaIndex, CrewAI and AutoGen describe a tool's arguments with a pydantic
model class, not a JSON-schema dict. `args_model(spec)` builds one from
`spec.parameters` (itself derived from the OpenAPI document), so no adapter
hand-writes a field list. Required properties are required; every other one
is Optional with default None, and `body(...)` drops the Nones again, so the
server sees exactly the fields the model supplied.

pydantic is imported inside `args_model`, never at module top. Every
framework that needs this module already depends on pydantic; the base
install does not.
"""
from __future__ import annotations

from typing import Any, Optional

__all__ = ["args_model", "body", "JSON_TYPES"]

#: JSON-schema type name to the Python type pydantic validates it as.
JSON_TYPES = {"string": str, "integer": int, "number": float,
              "boolean": bool, "object": dict, "array": list}


def _field_type(prop: dict):
    enum = prop.get("enum")
    if enum:
        from typing import Literal
        return Literal[tuple(enum)]
    return JSON_TYPES.get(prop.get("type"), Any)


def args_model(spec):
    """A pydantic model class named `<tool>_args` for one ToolSpec."""
    from pydantic import Field, create_model
    params = spec.parameters
    required = set(params.get("required", []))
    fields = {}
    for name, prop in params.get("properties", {}).items():
        t = _field_type(prop)
        desc = prop.get("description")
        if name in required:
            fields[name] = (t, Field(..., description=desc))
        else:
            fields[name] = (Optional[t], Field(None, description=desc))
    return create_model(f"{spec.name}_args", **fields)


def body(values: dict | None) -> dict:
    """The request body: the given arguments with unset (None) ones dropped."""
    return {k: v for k, v in (values or {}).items() if v is not None}
