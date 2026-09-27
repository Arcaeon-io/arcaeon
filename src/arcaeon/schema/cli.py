# SPDX-License-Identifier: MIT
"""`arcaeon schema --format FORMAT [--out FILE]` (K013, K081).

`openapi` (the default) prints the OpenAPI 3.1 document `arcaeon serve`
answers at /openapi.json, built from the same route table, so the two are
the same document. Every other format is GENERATED FROM THAT DOCUMENT, never
hand-written, through arcaeon.adapters.tool_specs (free check routes only):

  claude   Claude tool use: a list of {name, description, input_schema}
  openai   OpenAI function calling (Responses API shape): a list of
           {type: "function", name, description, parameters}; the Chat
           Completions shape nests the last three under `function`
  gemini   Gemini function declarations: a list of {name, description,
           parameters?}, the parameters cut to the OpenAPI subset Gemini's
           Schema reads (one type per node, `nullable` for a null type, no
           empty `required`, no `parameters` on a route that takes none)

`--out` writes the text to a file instead (UTF-8, LF), the way
docs/openapi.json and docs/schemas/*.json are made; a drift test holds each
committed file to this output.

Exit codes: 0 printed or written, 2 bad usage, 3 the file could not be written.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from arcaeon import verdict as V

FORMATS = ("openapi", "claude", "openai", "gemini")


def _dumps(obj) -> str:
    return json.dumps(obj, indent=1, ensure_ascii=True) + "\n"


def claude_tools(doc: dict | None = None) -> list[dict]:
    """Claude tool-use definitions, one per free check route."""
    from arcaeon.adapters import tool_specs
    return [{"name": s.name, "description": s.description, "input_schema": s.parameters}
            for s in tool_specs(doc=doc)]


def openai_functions(doc: dict | None = None) -> list[dict]:
    """OpenAI function tools, one per free check route. Not strict mode: the
    request schemas leave optional fields optional."""
    from arcaeon.adapters import tool_specs
    return [{"type": "function", "name": s.name, "description": s.description,
             "parameters": s.parameters}
            for s in tool_specs(doc=doc)]


#: The Schema fields Gemini's function declarations read; others are dropped.
GEMINI_SCHEMA_KEYS = frozenset({
    "type", "format", "description", "nullable", "enum", "properties", "required",
    "items", "minItems", "maxItems", "minLength", "maxLength", "minimum", "maximum"})


def gemini_schema(schema: dict) -> dict:
    """A JSON schema cut to what a Gemini function declaration accepts."""
    out: dict = {}
    for k, v in schema.items():
        if k not in GEMINI_SCHEMA_KEYS:
            continue
        if k == "type" and isinstance(v, list):
            real = [t for t in v if t != "null"]
            v = real[0] if real else "string"
            if "null" in schema["type"]:
                out["nullable"] = True
        elif k == "properties":
            v = {name: gemini_schema(sub) for name, sub in v.items()}
        elif k == "items":
            v = gemini_schema(v)
        elif k == "required":
            v = list(v)
            if not v:
                continue
        out[k] = v
    return out


def gemini_functions(doc: dict | None = None) -> list[dict]:
    """Gemini function declarations, one per free check route."""
    from arcaeon.adapters import tool_specs
    out = []
    for s in tool_specs(doc=doc):
        decl = {"name": s.name, "description": s.description}
        if s.parameters.get("properties"):
            decl["parameters"] = gemini_schema(s.parameters)
        out.append(decl)
    return out


_BUILDERS = {"claude": claude_tools, "openai": openai_functions,
             "gemini": gemini_functions}


def render(fmt: str) -> str:
    """The exact text `arcaeon schema --format FMT` prints."""
    from arcaeon.serve import openapi
    if fmt == "openapi":
        return openapi.dumps()
    doc = openapi.build()
    return _dumps(_BUILDERS[fmt](doc))


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="arcaeon schema",
        description="Print the local HTTP API as an OpenAPI 3.1 document (the one "
                    "`arcaeon serve` answers at /openapi.json), or as the tool schemas "
                    "a model framework reads, generated from that document.")
    ap.add_argument("--format", choices=FORMATS, default="openapi",
                    help="openapi (the default); claude: Claude tool-use definitions; "
                         "openai: OpenAI function tools; gemini: Gemini function "
                         "declarations")
    ap.add_argument("--out", default=None, metavar="FILE",
                    help="write the document to FILE instead of printing it")
    return ap


def main(argv: list[str] | None = None) -> int:
    try:
        a = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else V.EXIT_USAGE
    text = render(a.format)
    if a.out:
        try:
            Path(a.out).write_bytes(text.encode("utf-8"))
        except OSError as e:
            print(f"arcaeon schema: cannot write {a.out} ({e.strerror or type(e).__name__})",
                  file=sys.stderr)
            return V.EXIT_COULD_NOT_LOOK
        print(f"arcaeon schema: wrote {a.out}", file=sys.stderr)
        return V.EXIT_GOOD
    sys.stdout.write(text)
    return V.EXIT_GOOD
