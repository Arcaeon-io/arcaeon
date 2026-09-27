# SPDX-License-Identifier: MIT
"""A stdlib mini validator for request bodies: the small slice of JSON Schema
the route table uses, and nothing more.

Supported keywords: `type` (one name or a list), `required`, `properties`,
`enum`, `maxLength`, `items`. Anything else in a schema is ignored here (it
still reaches the OpenAPI document as written). Properties a schema does not
name are allowed through; a handler reads only what it knows.

`problems(schema, value)` returns every problem found, each naming the field
by its path (`body.fields.name`); `first_problem` returns one or None. The
server answers the first as a 400 `bad usage` body.
"""
from __future__ import annotations

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    # bool is an int in Python; in JSON it is not a number
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def _type_name(v) -> str:
    for name in ("null", "boolean", "integer", "number", "string", "array", "object"):
        if _TYPES[name](v):
            return name
    return type(v).__name__


def problems(schema: dict, value, where: str = "body") -> list[str]:
    """Every way `value` fails `schema`, as plain sentences naming the field."""
    out: list[str] = []
    want = schema.get("type")
    if want is not None:
        names = want if isinstance(want, list) else [want]
        unknown = [n for n in names if n not in _TYPES]
        if unknown:
            raise ValueError(f"schema at {where} names an unknown type {unknown[0]!r}")
        if not any(_TYPES[n](value) for n in names):
            out.append(f"{where} must be {' or '.join(names)}, got {_type_name(value)}")
            return out
    if "enum" in schema and value not in schema["enum"]:
        allowed = ", ".join(repr(x) for x in schema["enum"])
        out.append(f"{where} must be one of {allowed}, got {value!r}")
    if isinstance(value, str) and "maxLength" in schema and len(value) > schema["maxLength"]:
        out.append(f"{where} is {len(value)} characters, over the limit of "
                   f"{schema['maxLength']}")
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                out.append(f"missing required field '{name}' in {where}")
        for name, sub in schema.get("properties", {}).items():
            if name in value:
                out += problems(sub, value[name], f"{where}.{name}")
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for i, item in enumerate(value):
            out += problems(schema["items"], item, f"{where}[{i}]")
    return out


def first_problem(schema: dict, value, where: str = "body") -> str | None:
    found = problems(schema, value, where)
    return found[0] if found else None
